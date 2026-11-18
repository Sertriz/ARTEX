package nvdsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/cvematch"
)

// rec returns a full-size NVD 2.0 record: it carries fields the sync must drop
// (references, weaknesses, a secondary metric, a non-English description, a
// platform match that is not vulnerable).
func rec(id, lastMod, status, lo, hi string) map[string]any {
	return map[string]any{
		"id": id, "lastModified": lastMod, "vulnStatus": status, "published": "2020-01-01T00:00:00.000",
		"descriptions": []any{map[string]any{"lang": "es", "value": "no"}, map[string]any{"lang": "en", "value": "desc " + id}},
		"references":   []any{map[string]any{"url": "https://example.invalid/" + id}},
		"weaknesses":   []any{map[string]any{"source": "x"}},
		"metrics": map[string]any{
			"cvssMetricV31": []any{
				map[string]any{"type": "Secondary", "cvssData": map[string]any{"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "V/S"}},
				map[string]any{"type": "Primary", "cvssData": map[string]any{"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "V/P"}},
			},
			"ssvcV203": []any{map[string]any{"x": 1}},
		},
		"configurations": []any{map[string]any{"nodes": []any{map[string]any{"cpeMatch": []any{
			map[string]any{"vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionStartIncluding": lo, "versionEndExcluding": hi, "matchCriteriaId": "X"},
			map[string]any{"vulnerable": false, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
		}}}}},
	}
}

// fakeNVD serves pages of records, perPage at a time, and records each query.
type fakeNVD struct {
	mu      sync.Mutex
	records []map[string]any
	perPage int
	fail    []int // statuses to answer before succeeding, consumed in order
	queries []query
	keys    []string
}

type query = map[string]string

func (f *fakeNVD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := query{}
	for k, v := range r.URL.Query() {
		q[k] = v[0]
	}
	f.queries = append(f.queries, q)
	f.keys = append(f.keys, r.Header.Get("apiKey"))
	if len(f.fail) > 0 {
		code := f.fail[0]
		f.fail = f.fail[1:]
		w.Header().Set("message", "slow down")
		w.WriteHeader(code)
		return
	}
	start, _ := strconv.Atoi(q["startIndex"])
	end := min(start+f.perPage, len(f.records))
	var vulns []any
	for _, r := range f.records[min(start, len(f.records)):end] {
		vulns = append(vulns, map[string]any{"cve": r})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resultsPerPage": len(vulns), "startIndex": start, "totalResults": len(f.records),
		"format": "NVD_CVE", "version": "2.0", "vulnerabilities": vulns,
	})
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func options(t *testing.T, srv *httptest.Server, dir string, c *clock, sleeps *[]time.Duration) Options {
	t.Helper()
	return Options{
		Dir: dir, BaseURL: srv.URL, Client: srv.Client(), Now: c.now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			*sleeps = append(*sleeps, d)
			return ctx.Err()
		},
	}
}

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func TestFullThenIncremental(t *testing.T) {
	nvd := &fakeNVD{perPage: 2, records: []map[string]any{
		rec("CVE-2021-41617", "2024-01-01T00:00:00.000", "Analyzed", "6.2", "8.8"),
		rec("CVE-2021-0002", "2024-01-01T00:00:00.000", "Analyzed", "1.0", "2.0"),
		rec("CVE-2024-6387", "2024-07-01T00:00:00.000", "Modified", "8.6", "9.9"),
		rec("CVE-2023-0001", "2024-01-01T00:00:00.000", "Rejected", "1", "2"),
	}}
	srv := httptest.NewServer(nvd)
	defer srv.Close()
	dir := t.TempDir()
	// A stale year file from an earlier layout must not survive a full sync.
	if err := os.WriteFile(filepath.Join(dir, "nvd-1999.jsonl"), []byte(`{"id":"CVE-1999-0001"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &clock{t: t0}
	var sleeps []time.Duration
	o := options(t, srv, dir, c, &sleeps)
	o.APIKey = "k-123"

	st, err := Sync(context.Background(), o)
	if err != nil {
		t.Fatalf("full sync: %v", err)
	}
	if st.Mode != "full" || st.Requests != 2 || st.Received != 4 || st.Written != 3 || st.Files != 2 {
		t.Fatalf("full stats %+v", st)
	}
	if len(sleeps) != 1 || sleeps[0] != delayWithKey {
		t.Errorf("sleeps %v, want one %v pause between the two pages", sleeps, delayWithKey)
	}
	for _, k := range nvd.keys {
		if k != "k-123" {
			t.Errorf("apiKey header = %q", k)
		}
	}
	if q := nvd.queries[0]; q["resultsPerPage"] != "2000" || q["startIndex"] != "0" || q["lastModStartDate"] != "" {
		t.Errorf("full sync query %v", q)
	}
	if _, err := os.Stat(filepath.Join(dir, "nvd-1999.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Error("stale year file kept")
	}
	lines := readLines(t, filepath.Join(dir, "nvd-2021.jsonl"))
	if len(lines) != 2 {
		t.Fatalf("2021 lines = %d", len(lines))
	}
	// Trimmed: no references, weaknesses or SSVC; one English description; only the
	// primary metric; only vulnerable matches.
	l := lines[0]
	for _, k := range []string{"references", "weaknesses", "published"} {
		if _, ok := l[k]; ok {
			t.Errorf("trimmed record kept %q", k)
		}
	}
	if b, _ := json.Marshal(l); strings.Contains(string(b), "ssvc") || strings.Contains(string(b), `"no"`) ||
		strings.Contains(string(b), "linux_kernel") || strings.Contains(string(b), "MEDIUM") || strings.Contains(string(b), "matchCriteriaId") {
		t.Errorf("trimmed record = %s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "nvd-2023.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a year holding only a rejected record must not get a file")
	}
	stt, _ := ReadState(dir)
	if !stt.LastModEnd.Equal(t0) || !stt.LastFull.Equal(t0) {
		t.Errorf("state %+v", stt)
	}

	// The trimmed files load in the correlator and keep the primary metric.
	src, err := cvematch.LoadNVDDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s := src.Stats(); s.CVEs != 3 || s.ErrorFiles != 0 {
		t.Fatalf("loaded stats %+v", s)
	}
	got := cvematch.CorrelateResult(cvematch.Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.2p1"}}, src)
	if len(got.Confirmed()) != 1 || got.Confirmed()[0].CVE != "CVE-2021-41617" || got.Confirmed()[0].Severity != "CRITICAL" {
		t.Fatalf("correlation on synced feed: %+v", got.Candidates)
	}

	// Incremental, 200 days later: two lastMod windows. One record changed, one was
	// rejected, one is new in a new year.
	c.t = t0.Add(200 * 24 * time.Hour)
	nvd.queries, sleeps = nil, nil
	nvd.records = []map[string]any{
		rec("CVE-2021-41617", "2025-03-01T00:00:00.000", "Modified", "6.2", "8.9"),
		rec("CVE-2021-0002", "2025-03-01T00:00:00.000", "Rejected", "1", "2"),
		rec("CVE-2025-0001", "2025-03-01T00:00:00.000", "Analyzed", "1", "2"),
	}
	nvd.perPage = 10
	st, err = Sync(context.Background(), o)
	if err != nil {
		t.Fatalf("incremental: %v", err)
	}
	// The fake ignores the dates, so each of the two windows returns all three.
	if st.Mode != "incremental" || st.Requests != 2 || st.Written != 2 || st.Removed != 1 || st.Files != 2 {
		t.Fatalf("incremental stats %+v", st)
	}
	w1, w2 := nvd.queries[0], nvd.queries[1]
	if w1["lastModStartDate"] != "2024-12-31T23:55:00.000+00:00" || w1["lastModEndDate"] != "2025-04-30T23:55:00.000+00:00" ||
		w2["lastModStartDate"] != "2025-04-30T23:55:00.000+00:00" || w2["lastModEndDate"] != "2025-07-20T00:00:00.000+00:00" {
		t.Errorf("windows %v / %v", w1, w2)
	}
	lines = readLines(t, filepath.Join(dir, "nvd-2021.jsonl"))
	if len(lines) != 1 || lines[0]["vulnStatus"] != "Modified" {
		t.Fatalf("2021 after merge = %v", lines)
	}
	if lines = readLines(t, filepath.Join(dir, "nvd-2025.jsonl")); len(lines) != 1 {
		t.Fatalf("2025 = %v", lines)
	}
	if stt, _ := ReadState(dir); !stt.LastModEnd.Equal(c.t) || !stt.LastFull.Equal(t0) {
		t.Errorf("state after incremental %+v", stt)
	}
	// No temporary or lock file is left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") || e.Name() == lockName {
			t.Errorf("left behind: %s", e.Name())
		}
	}
}

func TestMergeRemovesEmptiedYear(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nvd-2020.jsonl"), []byte(`{"id":"CVE-2020-0001"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, r, err := mergeYear(dir, "2020", map[string][]byte{"CVE-2020-0001": nil})
	if err != nil || w != 0 || r != 1 {
		t.Fatalf("merge: %d %d %v", w, r, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "nvd-2020.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an emptied year file must be removed")
	}
}

func TestRetryThenSucceed(t *testing.T) {
	nvd := &fakeNVD{perPage: 5, fail: []int{403, 503}, records: []map[string]any{rec("CVE-2021-0001", "", "Analyzed", "1", "2")}}
	srv := httptest.NewServer(nvd)
	defer srv.Close()
	var sleeps []time.Duration
	o := options(t, srv, t.TempDir(), &clock{t: time.Unix(0, 0)}, &sleeps)
	st, err := Sync(context.Background(), o)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if st.Requests != 1 || len(nvd.queries) != 3 {
		t.Errorf("requests=%d http=%d", st.Requests, len(nvd.queries))
	}
	// Backoff doubles from the no-key delay.
	if len(sleeps) != 2 || sleeps[0] != 2*delayNoKey || sleeps[1] != 4*delayNoKey {
		t.Errorf("backoff sleeps %v", sleeps)
	}
}

func TestNonRetryableFails(t *testing.T) {
	nvd := &fakeNVD{perPage: 5, fail: []int{400}}
	srv := httptest.NewServer(nvd)
	defer srv.Close()
	var sleeps []time.Duration
	dir := t.TempDir()
	_, err := Sync(context.Background(), options(t, srv, dir, &clock{t: time.Unix(0, 0)}, &sleeps))
	if err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "slow down") {
		t.Fatalf("err = %v", err)
	}
	if len(nvd.queries) != 1 {
		t.Errorf("a 400 must not be retried: %d requests", len(nvd.queries))
	}
	if st, _ := ReadState(dir); !st.LastModEnd.IsZero() {
		t.Error("a failed sync must not record state")
	}
}

func TestEmptyPageBeforeTotalIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"resultsPerPage":0,"startIndex":0,"totalResults":5,"vulnerabilities":[]}`)
	}))
	defer srv.Close()
	var sleeps []time.Duration
	if _, err := Sync(context.Background(), options(t, srv, t.TempDir(), &clock{t: time.Unix(0, 0)}, &sleeps)); err == nil {
		t.Fatal("an empty page before the total must be an error, not an endless loop")
	}
}

func TestLock(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	unlock, err := lock(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock(dir, now); !errors.Is(err, ErrBusy) {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	// A lock left by a dead sync is taken over once stale.
	p := filepath.Join(dir, lockName)
	if err := os.WriteFile(p, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-2 * staleLock)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	unlock, err = lock(dir, now)
	if err != nil {
		t.Fatalf("stale lock not taken over: %v", err)
	}
	unlock()
}

func TestCancelDuringPause(t *testing.T) {
	nvd := &fakeNVD{perPage: 1, records: []map[string]any{rec("CVE-2021-0001", "", "A", "1", "2"), rec("CVE-2021-0002", "", "A", "1", "2")}}
	srv := httptest.NewServer(nvd)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	o := Options{Dir: dir, BaseURL: srv.URL, Client: srv.Client(), Now: time.Now,
		Sleep: func(context.Context, time.Duration) error { cancel(); return context.Canceled }}
	if _, err := Sync(ctx, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != stateName { // nothing but possibly a state file... which must not exist either
			if strings.HasSuffix(e.Name(), ".tmp") || e.Name() == lockName || strings.HasPrefix(e.Name(), "nvd-") {
				t.Errorf("a cancelled full sync left %s", e.Name())
			}
		}
	}
}

func TestSlimRejectsBadID(t *testing.T) {
	if _, _, err := slim(json.RawMessage(`{"id":"../../etc/passwd"}`)); err == nil {
		t.Fatal("a record with a malformed id must be refused")
	}
}

func TestNVDTime(t *testing.T) {
	if got := nvdTime(time.Date(2024, 1, 2, 3, 4, 5, 6e6, time.FixedZone("x", 3600))); got != "2024-01-02T02:04:05.006+00:00" {
		t.Errorf("nvdTime = %q", got)
	}
}
