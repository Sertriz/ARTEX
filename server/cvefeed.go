package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/cvematch"
	"github.com/Autumn-27/artex/cvematch/nvdsync"
)

// CVE feed: the local NVD feed the correlator reads, its hot reload, and its
// sync from the NVD API (on demand, and on a schedule when configured).
//
//	ARTEX_CVE_FEED_DIR       the feed directory; unset = the feature is off
//	ARTEX_NVD_API_KEY        optional NVD API key (raises the API rate limit)
//	ARTEX_CVE_SYNC_INTERVAL  optional auto-sync period ("24h", at least 1h)
//
// Loading the feed IS the opt-in: with no directory, or one holding no CVE, no
// source is installed and scan ingestion behaves exactly as before.

const cveSyncMinInterval = time.Hour

var (
	errCVEFeedOff  = errors.New("the CVE feed is not configured: set ARTEX_CVE_FEED_DIR")
	errCVESyncBusy = errors.New("a CVE feed sync is already running")
)

type cveFeed struct {
	dir      string
	apiKey   string
	interval time.Duration

	reloadMu sync.Mutex // one load at a time: a load holds a whole index in memory

	mu        sync.Mutex
	loaded    cvematch.LoadStats
	loadedAt  time.Time
	loadErr   string
	active    bool
	syncing   bool
	syncStart time.Time
	lastSync  *nvdsync.Stats
	syncAt    time.Time
	syncErr   string

	// seams for tests
	syncFn  func(context.Context, nvdsync.Options) (nvdsync.Stats, error)
	install func(cvematch.Source)
	now     func() time.Time
}

func newCVEFeedFromEnv() *cveFeed {
	f := &cveFeed{
		dir:     strings.TrimSpace(os.Getenv("ARTEX_CVE_FEED_DIR")),
		apiKey:  strings.TrimSpace(os.Getenv("ARTEX_NVD_API_KEY")),
		syncFn:  nvdsync.Sync,
		install: agent.SetCVESource,
		now:     time.Now,
	}
	if v := strings.TrimSpace(os.Getenv("ARTEX_CVE_SYNC_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		switch {
		case err != nil:
			log.Printf("[cve] ARTEX_CVE_SYNC_INTERVAL=%q is not a duration; auto-sync off", v)
		case d < cveSyncMinInterval:
			log.Printf("[cve] ARTEX_CVE_SYNC_INTERVAL=%s is under %s; auto-sync off", d, cveSyncMinInterval)
		default:
			f.interval = d
		}
	}
	return f
}

func (f *cveFeed) enabled() bool { return f != nil && f.dir != "" }

// reload loads the feed directory and installs it as the correlator's source. A
// directory with no CVE uninstalls the source. A failed load keeps the source
// already installed, so a transient error never switches correlation off.
func (f *cveFeed) reload() error {
	if !f.enabled() {
		return errCVEFeedOff
	}
	f.reloadMu.Lock()
	defer f.reloadMu.Unlock()
	src, err := cvematch.LoadNVDDir(f.dir)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		f.loadErr = err.Error()
		log.Printf("[cve] feed dir %q not loaded: %v", f.dir, err)
		return err
	}
	st := src.Stats()
	f.loaded, f.loadedAt, f.loadErr = st, f.now(), ""
	if st.CVEs == 0 {
		f.install(nil)
		f.active = false
		log.Printf("[cve] feed dir %q: %d file(s), %d with errors, no CVE indexed; correlation off", f.dir, st.Files, st.ErrorFiles)
		return nil
	}
	f.install(src)
	f.active = true
	log.Printf("[cve] correlation on: %d CVEs, %d products, %d records from %d file(s) in %q (%d with errors)",
		st.CVEs, st.Products, st.Records, st.Files, f.dir, st.ErrorFiles)
	return nil
}

// startSync runs one sync in the background, then reloads the feed. ctx bounds
// the sync (the server's lifetime, not a request's).
func (f *cveFeed) startSync(ctx context.Context, full bool) error {
	if !f.enabled() {
		return errCVEFeedOff
	}
	f.mu.Lock()
	if f.syncing {
		f.mu.Unlock()
		return errCVESyncBusy
	}
	f.syncing, f.syncStart = true, f.now()
	f.mu.Unlock()
	go f.runSync(ctx, full)
	return nil
}

func (f *cveFeed) runSync(ctx context.Context, full bool) {
	st, err := f.syncFn(ctx, nvdsync.Options{
		Dir: f.dir, APIKey: f.apiKey, Full: full,
		Logf: func(format string, args ...any) { log.Printf(format, args...) },
	})
	f.mu.Lock()
	f.syncing, f.syncAt = false, f.now()
	if err != nil {
		f.syncErr = err.Error()
		log.Printf("[cve] sync failed: %v", err)
	} else {
		f.syncErr, f.lastSync = "", &st
	}
	f.mu.Unlock()
	if err == nil {
		_ = f.reload()
	}
}

// autoSync syncs every interval until ctx ends. The first sync runs shortly after
// startup when the feed is older than one interval (or was never synced).
func (f *cveFeed) autoSync(ctx context.Context) {
	if !f.enabled() || f.interval <= 0 {
		return
	}
	log.Printf("[cve] auto-sync every %s into %q", f.interval, f.dir)
	first := time.Minute
	if st, err := nvdsync.ReadState(f.dir); err == nil && !st.LastModEnd.IsZero() {
		if age := f.now().Sub(st.LastModEnd); age < f.interval {
			first = f.interval - age
		}
	}
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := f.startSync(ctx, false); err != nil && !errors.Is(err, errCVESyncBusy) {
			log.Printf("[cve] auto-sync: %v", err)
		}
		t.Reset(f.interval)
	}
}

func timeOrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// status reports the feed's configuration, load and sync state. The API key is
// reported as configured or not, never by value.
func (f *cveFeed) status() map[string]any {
	if !f.enabled() {
		return map[string]any{"enabled": false, "active": false,
			"hint": "set ARTEX_CVE_FEED_DIR to a directory for the NVD feed, then sync it"}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	syncInfo := map[string]any{
		"running": f.syncing, "started_at": nil, "last": f.lastSync, "last_at": timeOrNil(f.syncAt),
		"last_error": f.syncErr, "interval": "", "api_key_configured": f.apiKey != "",
	}
	if f.syncing {
		syncInfo["started_at"] = timeOrNil(f.syncStart)
	}
	if f.interval > 0 {
		syncInfo["interval"] = f.interval.String()
	}
	if st, err := nvdsync.ReadState(f.dir); err == nil {
		syncInfo["feed_last_modified"] = timeOrNil(st.LastModEnd)
		syncInfo["feed_last_full_sync"] = timeOrNil(st.LastFull)
	}
	return map[string]any{
		"enabled": true, "dir": f.dir, "active": f.active,
		"loaded":    f.loaded,
		"loaded_at": timeOrNil(f.loadedAt), "load_error": f.loadErr,
		"sync": syncInfo,
	}
}

// ---- HTTP ----

// GET /api/settings/cve
func (s *Server) cveStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.m.cve.status())
}

// POST /api/settings/cve/reload — reread the feed directory.
func (s *Server) cveReload(w http.ResponseWriter, r *http.Request) {
	f := s.m.cve
	if !f.enabled() {
		writeErr(w, 409, errCVEFeedOff.Error())
		return
	}
	if err := f.reload(); err != nil {
		writeErr(w, 500, "reload failed: "+err.Error())
		return
	}
	writeJSON(w, 200, f.status())
}

// POST /api/settings/cve/sync {"full": bool} — start a sync from the NVD API;
// the feed is reloaded when it finishes.
func (s *Server) cveSync(w http.ResponseWriter, r *http.Request) {
	f := s.m.cve
	var body struct {
		Full bool `json:"full"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, 400, "invalid body")
			return
		}
	}
	switch err := f.startSync(s.ctx, body.Full); {
	case errors.Is(err, errCVEFeedOff), errors.Is(err, errCVESyncBusy):
		writeErr(w, 409, err.Error())
		return
	case err != nil:
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 202, f.status())
}
