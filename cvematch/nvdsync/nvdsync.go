// Package nvdsync keeps a local CVE feed directory in step with the NVD CVE API
// 2.0, for the cvematch correlator. A full sync pages through every CVE; later
// syncs fetch only what changed since the last one (lastModStartDate /
// lastModEndDate, in windows of at most 120 days as the API requires).
//
// Records are written trimmed to the fields correlation reads (id, lastModified,
// vulnStatus, English description, primary CVSS base metrics, vulnerable
// configurations), one bare NVD 2.0 record per line, in one file per CVE year
// (nvd-<year>.jsonl). Every file is replaced atomically, and the state, lock and
// temporary files are dot-files, so a concurrent cvematch.LoadNVDDir never reads a
// half-written file.
//
// The sync talks to the NVD only. It is not target traffic: it uses its own HTTP
// client (honoring HTTPS_PROXY), not the scan egress path.
package nvdsync

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the NVD CVE API 2.0 endpoint.
const DefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

const (
	pageSize  = 2000                 // the API's maximum resultsPerPage
	maxWindow = 120 * 24 * time.Hour // the API's maximum lastMod date range
	// windowOverlap re-reads a little of the previous window so a record
	// modified while the last sync ran is not missed. Re-reading is harmless.
	windowOverlap = 5 * time.Minute
	stateName     = ".nvd-sync.json"
	lockName      = ".nvd-sync.lock"
	staleLock     = 12 * time.Hour
	userAgent     = "artex-cve-sync"
	maxBodyBytes  = 512 << 20 // one API page; a full page is tens of MB
	// NVD guidance: sleep about six seconds between requests without an API key
	// (5 requests / 30 s); with a key the limit is 50 requests / 30 s.
	delayNoKey   = 6 * time.Second
	delayWithKey = 1 * time.Second
)

// Options configures one sync.
type Options struct {
	Dir     string // the feed directory (created if missing)
	APIKey  string // optional NVD API key, sent as the apiKey header
	BaseURL string // defaults to DefaultBaseURL
	Client  *http.Client
	Full    bool          // force a full sync even when an earlier one is recorded
	Delay   time.Duration // pause between requests; 0 = NVD guidance for the key state
	Retries int           // attempts per request on a transient failure; 0 = 6

	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	Logf  func(format string, args ...any)
}

// Stats describes one sync.
type Stats struct {
	Mode     string    `json:"mode"` // "full" or "incremental"
	Since    time.Time `json:"since,omitempty"`
	Until    time.Time `json:"until"`
	Requests int       `json:"requests"`
	Received int       `json:"received"` // records received from the API
	Written  int       `json:"written"`  // records added or replaced on disk
	Removed  int       `json:"removed"`  // records removed (rejected by NVD)
	Files    int       `json:"files"`    // year files written
}

// State is what the feed directory remembers between syncs.
type State struct {
	LastModEnd time.Time `json:"last_mod_end"`
	LastFull   time.Time `json:"last_full_sync"`
}

// ReadState returns the sync state recorded in dir (zero when none).
func ReadState(dir string) (State, error) {
	var st State
	b, err := os.ReadFile(filepath.Join(dir, stateName))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

// ErrBusy is returned when another sync holds the directory's lock.
var ErrBusy = errors.New("another CVE feed sync is running on this directory")

// Sync brings dir up to date: a full sync when none was recorded (or Full is
// set), otherwise an incremental one from the last recorded end.
func Sync(ctx context.Context, o Options) (Stats, error) {
	o = o.withDefaults()
	if strings.TrimSpace(o.Dir) == "" {
		return Stats{}, errors.New("no feed directory")
	}
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return Stats{}, err
	}
	unlock, err := lock(o.Dir, o.Now())
	if err != nil {
		return Stats{}, err
	}
	defer unlock()

	st, err := ReadState(o.Dir)
	if err != nil {
		return Stats{}, fmt.Errorf("sync state: %w", err)
	}
	if o.Full || st.LastModEnd.IsZero() {
		return o.full(ctx)
	}
	return o.incremental(ctx, st)
}

func (o Options) withDefaults() Options {
	if o.BaseURL == "" {
		o.BaseURL = DefaultBaseURL
	}
	if o.Client == nil {
		o.Client = &http.Client{
			Timeout:   5 * time.Minute,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 30 * time.Second},
		}
	}
	if o.Delay == 0 {
		o.Delay = delayNoKey
		if o.APIKey != "" {
			o.Delay = delayWithKey
		}
	}
	if o.Retries <= 0 {
		o.Retries = 6
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	return o
}

// lock takes the directory's sync lock. A lock older than staleLock is taken
// over: a sync never runs that long, so its owner died.
func lock(dir string, now time.Time) (func(), error) {
	p := filepath.Join(dir, lockName)
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(p) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if fi, serr := os.Stat(p); serr == nil && now.Sub(fi.ModTime()) > staleLock {
			_ = os.Remove(p)
			continue
		}
		return nil, ErrBusy
	}
	return nil, ErrBusy
}

// full pages through every CVE and replaces all year files.
func (o Options) full(ctx context.Context) (Stats, error) {
	until := o.Now().UTC()
	stats := Stats{Mode: "full", Until: until}
	o.Logf("[cve-sync] full sync into %s", o.Dir)
	w := newYearWriters(o.Dir)
	defer w.abort()
	err := o.fetchAll(ctx, nil, &stats, func(rec slimRecord, line []byte) error {
		if rec.rejected() {
			return nil
		}
		stats.Written++
		return w.write(rec.year(), line)
	})
	if err != nil {
		return stats, err
	}
	files, err := w.commit()
	if err != nil {
		return stats, err
	}
	stats.Files = len(files)
	// A year no longer present (all its records rejected) must not keep stale data.
	if err := removeOtherYearFiles(o.Dir, files); err != nil {
		return stats, err
	}
	if err := writeState(o.Dir, State{LastModEnd: until, LastFull: until}); err != nil {
		return stats, err
	}
	o.Logf("[cve-sync] full sync done: %d records in %d files, %d requests", stats.Written, stats.Files, stats.Requests)
	return stats, nil
}

// incremental fetches the records modified since the last sync and merges them
// into their year files.
func (o Options) incremental(ctx context.Context, prev State) (Stats, error) {
	until := o.Now().UTC()
	since := prev.LastModEnd.Add(-windowOverlap).UTC()
	stats := Stats{Mode: "incremental", Since: since, Until: until}
	o.Logf("[cve-sync] incremental sync %s .. %s", since.Format(time.RFC3339), until.Format(time.RFC3339))
	changes := map[string]map[string][]byte{} // year -> id -> line (nil = remove)
	for start := since; start.Before(until); start = start.Add(maxWindow) {
		end := start.Add(maxWindow)
		if end.After(until) {
			end = until
		}
		q := url.Values{}
		q.Set("lastModStartDate", nvdTime(start))
		q.Set("lastModEndDate", nvdTime(end))
		err := o.fetchAll(ctx, q, &stats, func(rec slimRecord, line []byte) error {
			y := rec.year()
			if changes[y] == nil {
				changes[y] = map[string][]byte{}
			}
			if rec.rejected() {
				changes[y][rec.ID] = nil
			} else {
				changes[y][rec.ID] = line
			}
			return nil
		})
		if err != nil {
			return stats, err
		}
	}
	years := make([]string, 0, len(changes))
	for y := range changes {
		years = append(years, y)
	}
	sort.Strings(years)
	for _, y := range years {
		written, removed, err := mergeYear(o.Dir, y, changes[y])
		if err != nil {
			return stats, fmt.Errorf("merge %s: %w", yearFile(y), err)
		}
		stats.Written += written
		stats.Removed += removed
		stats.Files++
	}
	if err := writeState(o.Dir, State{LastModEnd: until, LastFull: prev.LastFull}); err != nil {
		return stats, err
	}
	o.Logf("[cve-sync] incremental sync done: %d received, %d written, %d removed, %d files", stats.Received, stats.Written, stats.Removed, stats.Files)
	return stats, nil
}

// nvdTime formats a time the way the API's date parameters expect, with an
// explicit offset ("2024-01-02T03:04:05.000+00:00").
func nvdTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000-07:00") }

// apiPage is one API response page.
type apiPage struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE json.RawMessage `json:"cve"`
	} `json:"vulnerabilities"`
}

// fetchAll pages through one query, handing every trimmed record to emit.
func (o Options) fetchAll(ctx context.Context, q url.Values, stats *Stats, emit func(slimRecord, []byte) error) error {
	for start, total := 0, -1; total < 0 || start < total; {
		p := url.Values{}
		for k, v := range q {
			p[k] = v
		}
		p.Set("startIndex", strconv.Itoa(start))
		p.Set("resultsPerPage", strconv.Itoa(pageSize))
		if stats.Requests > 0 {
			if err := o.Sleep(ctx, o.Delay); err != nil {
				return err
			}
		}
		page, err := o.fetchPage(ctx, p)
		stats.Requests++
		if err != nil {
			return err
		}
		total = page.TotalResults
		for _, v := range page.Vulnerabilities {
			rec, line, err := slim(v.CVE)
			if err != nil {
				return fmt.Errorf("record at index %d: %w", start, err)
			}
			stats.Received++
			if err := emit(rec, line); err != nil {
				return err
			}
		}
		if len(page.Vulnerabilities) == 0 {
			if start < total {
				return fmt.Errorf("NVD returned an empty page at index %d of %d", start, total)
			}
			break
		}
		start += len(page.Vulnerabilities)
		if total > 0 {
			o.Logf("[cve-sync] %d / %d", min(start, total), total)
		}
	}
	return nil
}

// retryable reports whether an HTTP status is worth retrying. NVD answers 403
// when a client exceeds its rate limit.
func retryable(code int) bool {
	switch code {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func (o Options) fetchPage(ctx context.Context, q url.Values) (*apiPage, error) {
	var lastErr error
	for attempt := 0; attempt < o.Retries; attempt++ {
		if attempt > 0 {
			wait := min(o.Delay*time.Duration(1<<attempt), 2*time.Minute)
			o.Logf("[cve-sync] retry %d after %v: %v", attempt, wait, lastErr)
			if err := o.Sleep(ctx, wait); err != nil {
				return nil, err
			}
		}
		page, retry, err := o.fetchOnce(ctx, q)
		if err == nil {
			return page, nil
		}
		if !retry {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("NVD request failed after %d attempts: %w", o.Retries, lastErr)
}

func (o Options) fetchOnce(ctx context.Context, q url.Values) (page *apiPage, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.BaseURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if o.APIKey != "" {
		req.Header.Set("apiKey", o.APIKey)
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		// The message header NVD sets on errors is short and server-written.
		msg := strings.TrimSpace(resp.Header.Get("message"))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		err := fmt.Errorf("NVD answered %s", resp.Status)
		if msg != "" {
			err = fmt.Errorf("NVD answered %s: %s", resp.Status, msg)
		}
		return nil, retryable(resp.StatusCode), err
	}
	var p apiPage
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes))
	if err := dec.Decode(&p); err != nil {
		return nil, true, fmt.Errorf("decode NVD page: %w", err)
	}
	return &p, false, nil
}

// ---- trimmed records ----

// slimRecord is the subset of an NVD 2.0 CVE record that correlation reads. It
// marshals back to a valid (smaller) NVD 2.0 record.
type slimRecord struct {
	ID             string         `json:"id"`
	LastModified   string         `json:"lastModified,omitempty"`
	VulnStatus     string         `json:"vulnStatus,omitempty"`
	Descriptions   []slimDesc     `json:"descriptions,omitempty"`
	Metrics        map[string]any `json:"metrics,omitempty"`
	Configurations []slimConfig   `json:"configurations,omitempty"`
}

type slimDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type slimConfig struct {
	Nodes []slimNode `json:"nodes"`
}

type slimNode struct {
	CPEMatch []slimMatch `json:"cpeMatch"`
}

type slimMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

type rawMetric struct {
	Type         string `json:"type,omitempty"`
	BaseSeverity string `json:"baseSeverity,omitempty"`
	CVSSData     struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity,omitempty"`
		VectorString string  `json:"vectorString,omitempty"`
	} `json:"cvssData"`
}

var cveIDRe = regexp.MustCompile(`^CVE-([0-9]{4})-[0-9]{4,}$`)

func (r slimRecord) rejected() bool { return strings.EqualFold(r.VulnStatus, "rejected") }

func (r slimRecord) year() string {
	if m := cveIDRe.FindStringSubmatch(r.ID); m != nil {
		return m[1]
	}
	return "other"
}

// slim trims one raw NVD record to what correlation reads and returns it with its
// one-line JSON form.
func slim(raw json.RawMessage) (slimRecord, []byte, error) {
	var in struct {
		ID             string                     `json:"id"`
		LastModified   string                     `json:"lastModified"`
		VulnStatus     string                     `json:"vulnStatus"`
		Descriptions   []slimDesc                 `json:"descriptions"`
		Metrics        map[string]json.RawMessage `json:"metrics"`
		Configurations []slimConfig               `json:"configurations"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return slimRecord{}, nil, err
	}
	if !cveIDRe.MatchString(in.ID) {
		return slimRecord{}, nil, fmt.Errorf("unexpected CVE id %q", in.ID)
	}
	out := slimRecord{ID: in.ID, LastModified: in.LastModified, VulnStatus: in.VulnStatus}
	for _, d := range in.Descriptions {
		if strings.EqualFold(d.Lang, "en") {
			out.Descriptions = []slimDesc{d}
			break
		}
	}
	for _, k := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		var ms []rawMetric
		if json.Unmarshal(in.Metrics[k], &ms) != nil || len(ms) == 0 {
			continue
		}
		pick := ms[0]
		for _, m := range ms {
			if strings.EqualFold(m.Type, "primary") {
				pick = m
				break
			}
		}
		if out.Metrics == nil {
			out.Metrics = map[string]any{}
		}
		out.Metrics[k] = []rawMetric{pick}
	}
	for _, c := range in.Configurations {
		var cfg slimConfig
		for _, n := range c.Nodes {
			var node slimNode
			for _, m := range n.CPEMatch {
				if m.Vulnerable && m.Criteria != "" {
					node.CPEMatch = append(node.CPEMatch, m)
				}
			}
			if len(node.CPEMatch) > 0 {
				cfg.Nodes = append(cfg.Nodes, node)
			}
		}
		if len(cfg.Nodes) > 0 {
			out.Configurations = append(out.Configurations, cfg)
		}
	}
	line, err := json.Marshal(out)
	return out, line, err
}

// ---- year files ----

func yearFile(year string) string { return "nvd-" + year + ".jsonl" }

var yearFileRe = regexp.MustCompile(`^nvd-([0-9]{4}|other)\.jsonl$`)

// yearWriters streams a full sync into one temporary file per year.
type yearWriters struct {
	dir   string
	files map[string]*os.File
	bufs  map[string]*bufio.Writer
}

func newYearWriters(dir string) *yearWriters {
	return &yearWriters{dir: dir, files: map[string]*os.File{}, bufs: map[string]*bufio.Writer{}}
}

func tmpName(dir, year string) string { return filepath.Join(dir, "."+yearFile(year)+".tmp") }

func (w *yearWriters) write(year string, line []byte) error {
	b := w.bufs[year]
	if b == nil {
		f, err := os.Create(tmpName(w.dir, year))
		if err != nil {
			return err
		}
		w.files[year] = f
		b = bufio.NewWriterSize(f, 1<<16)
		w.bufs[year] = b
	}
	if _, err := b.Write(line); err != nil {
		return err
	}
	return b.WriteByte('\n')
}

// commit flushes, syncs and renames every temporary file into place.
func (w *yearWriters) commit() ([]string, error) {
	var names []string
	for year, f := range w.files {
		if err := w.bufs[year].Flush(); err != nil {
			return nil, err
		}
		if err := f.Sync(); err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		if err := os.Rename(tmpName(w.dir, year), filepath.Join(w.dir, yearFile(year))); err != nil {
			return nil, err
		}
		names = append(names, yearFile(year))
		delete(w.files, year)
	}
	sort.Strings(names)
	return names, nil
}

// abort removes any temporary file left by a failed sync.
func (w *yearWriters) abort() {
	for year, f := range w.files {
		_ = f.Close()
		_ = os.Remove(tmpName(w.dir, year))
	}
}

func removeOtherYearFiles(dir string, keep []string) error {
	k := map[string]bool{}
	for _, n := range keep {
		k[n] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() && yearFileRe.MatchString(e.Name()) && !k[e.Name()] {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// mergeYear rewrites one year file with the changed records: a changed record
// replaces its old line, a nil change removes it, new records are appended.
func mergeYear(dir, year string, changes map[string][]byte) (written, removed int, err error) {
	final := filepath.Join(dir, yearFile(year))
	tmp := tmpName(dir, year)
	out, err := os.Create(tmp)
	if err != nil {
		return 0, 0, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = out.Close()
			_ = os.Remove(tmp)
		}
	}()
	bw := bufio.NewWriterSize(out, 1<<16)
	done := map[string]bool{}
	lines := 0
	if in, err := os.Open(final); err == nil {
		sc := bufio.NewScanner(in)
		sc.Buffer(make([]byte, 0, 1<<16), 64<<20)
		for sc.Scan() {
			line := sc.Bytes()
			if len(strings.TrimSpace(string(line))) == 0 {
				continue
			}
			var head struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(line, &head)
			if repl, changed := changes[head.ID]; changed && head.ID != "" {
				if done[head.ID] {
					continue // a duplicate line of an already merged record
				}
				done[head.ID] = true
				if repl == nil {
					removed++
					continue
				}
				line = repl
				written++
			}
			if _, err := bw.Write(line); err != nil {
				in.Close()
				return 0, 0, err
			}
			_ = bw.WriteByte('\n')
			lines++
		}
		serr := sc.Err()
		in.Close()
		if serr != nil {
			return 0, 0, serr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, 0, err
	}
	ids := make([]string, 0, len(changes))
	for id := range changes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if done[id] || changes[id] == nil {
			continue
		}
		if _, err := bw.Write(changes[id]); err != nil {
			return 0, 0, err
		}
		_ = bw.WriteByte('\n')
		written++
		lines++
	}
	if err := bw.Flush(); err != nil {
		return 0, 0, err
	}
	if err := out.Sync(); err != nil {
		return 0, 0, err
	}
	if err := out.Close(); err != nil {
		return 0, 0, err
	}
	ok = true
	if lines == 0 {
		// Every record of the year was removed: drop the file rather than leave an
		// empty one, which the loader would report as unreadable.
		_ = os.Remove(tmp)
		if err := os.Remove(final); err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, 0, err
		}
		return written, removed, nil
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return 0, 0, err
	}
	return written, removed, nil
}

func writeState(dir string, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, stateName+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, stateName))
}
