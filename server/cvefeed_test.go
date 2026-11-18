package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/cvematch"
	"github.com/Autumn-27/artex/cvematch/nvdsync"
)

// copyTestFeed copies the real NVD records from cvematch/testdata/nvd.
func copyTestFeed(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join("..", "cvematch", "testdata", "nvd")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type installRecorder struct {
	mu  sync.Mutex
	src []cvematch.Source
}

func (r *installRecorder) install(s cvematch.Source) {
	r.mu.Lock()
	r.src = append(r.src, s)
	r.mu.Unlock()
}

func (r *installRecorder) last() cvematch.Source {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.src) == 0 {
		return nil
	}
	return r.src[len(r.src)-1]
}

func testFeed(dir string, rec *installRecorder) *cveFeed {
	return &cveFeed{dir: dir, syncFn: nvdsync.Sync, install: rec.install, now: time.Now}
}

func TestCVEFeedDisabled(t *testing.T) {
	var f *cveFeed
	if f.enabled() {
		t.Fatal("nil feed enabled")
	}
	if st := f.status(); st["enabled"] != false {
		t.Errorf("status %v", st)
	}
	f = &cveFeed{}
	if err := f.reload(); !errors.Is(err, errCVEFeedOff) {
		t.Errorf("reload: %v", err)
	}
	if err := f.startSync(context.Background(), false); !errors.Is(err, errCVEFeedOff) {
		t.Errorf("sync: %v", err)
	}
	f.autoSync(context.Background()) // returns at once
}

func TestCVEFeedReload(t *testing.T) {
	rec := &installRecorder{}
	f := testFeed(copyTestFeed(t), rec)
	if err := f.reload(); err != nil {
		t.Fatal(err)
	}
	if rec.last() == nil {
		t.Fatal("no source installed")
	}
	st := f.status()
	if st["active"] != true || st["loaded"].(cvematch.LoadStats).CVEs != 19 {
		t.Fatalf("status %v", st)
	}

	// A failed reload keeps the installed source.
	working := rec.last()
	f.dir = filepath.Join(t.TempDir(), "gone")
	if err := f.reload(); err == nil {
		t.Fatal("expected an error for a missing dir")
	}
	if rec.last() != working || f.status()["load_error"] == "" {
		t.Error("a failed reload must keep the working source and report the error")
	}

	// A directory with no CVE uninstalls the source.
	f.dir = t.TempDir()
	if err := f.reload(); err != nil {
		t.Fatal(err)
	}
	if rec.last() != nil || f.status()["active"] != false {
		t.Error("an empty feed must switch correlation off")
	}
}

func TestCVEFeedSync(t *testing.T) {
	rec := &installRecorder{}
	f := testFeed(copyTestFeed(t), rec)
	release := make(chan struct{})
	calls := make(chan nvdsync.Options, 2)
	f.syncFn = func(ctx context.Context, o nvdsync.Options) (nvdsync.Stats, error) {
		calls <- o
		<-release
		return nvdsync.Stats{Mode: "incremental", Written: 3}, nil
	}
	f.apiKey = "secret-key"
	if err := f.startSync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	o := <-calls
	if !o.Full || o.APIKey != "secret-key" || o.Dir != f.dir {
		t.Errorf("sync options %+v", o)
	}
	if err := f.startSync(context.Background(), false); !errors.Is(err, errCVESyncBusy) {
		t.Fatalf("second sync: %v", err)
	}
	st := f.status()
	if st["sync"].(map[string]any)["running"] != true {
		t.Errorf("status while running: %v", st)
	}
	if b, _ := json.Marshal(st); strings.Contains(string(b), "secret-key") {
		t.Fatal("the API key leaked into the status")
	}
	close(release)
	waitFor(t, func() bool { return rec.last() != nil }) // reloaded after the sync
	waitFor(t, func() bool { return f.status()["sync"].(map[string]any)["running"] == false })
	if s := f.status()["sync"].(map[string]any); s["last_error"] != "" || s["last"].(*nvdsync.Stats).Written != 3 {
		t.Errorf("sync status %v", s)
	}

	// A failed sync is reported and does not reload.
	installs := len(rec.src)
	f.syncFn = func(context.Context, nvdsync.Options) (nvdsync.Stats, error) {
		return nvdsync.Stats{}, errors.New("NVD answered 503")
	}
	if err := f.startSync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return f.status()["sync"].(map[string]any)["last_error"] == "NVD answered 503" })
	if len(rec.src) != installs {
		t.Error("a failed sync must not reload")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestCVEFeedHTTP(t *testing.T) {
	rec := &installRecorder{}
	f := testFeed(copyTestFeed(t), rec)
	f.syncFn = func(context.Context, nvdsync.Options) (nvdsync.Stats, error) { return nvdsync.Stats{}, nil }
	s := &Server{m: &Manager{cve: f}, ctx: context.Background()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/settings/cve", s.cveStatus)
	mux.HandleFunc("POST /api/settings/cve/reload", s.cveReload)
	mux.HandleFunc("POST /api/settings/cve/sync", s.cveSync)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	do := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return resp.StatusCode, m
	}
	if code, m := do("POST", "/api/settings/cve/reload", ""); code != 200 || m["active"] != true {
		t.Fatalf("reload: %d %v", code, m)
	}
	if code, m := do("GET", "/api/settings/cve", ""); code != 200 || m["loaded"].(map[string]any)["cves"].(float64) != 19 {
		t.Fatalf("status: %d %v", code, m)
	}
	if code, _ := do("POST", "/api/settings/cve/sync", `{"full":true}`); code != 202 {
		t.Fatalf("sync: %d", code)
	}
	if code, _ := do("POST", "/api/settings/cve/sync", `{not json`); code != 400 {
		t.Fatalf("bad body: %d", code)
	}

	s.m.cve = nil
	if code, m := do("GET", "/api/settings/cve", ""); code != 200 || m["enabled"] != false {
		t.Fatalf("disabled status: %d %v", code, m)
	}
	if code, _ := do("POST", "/api/settings/cve/reload", ""); code != 409 {
		t.Fatalf("disabled reload: %d", code)
	}
	if code, _ := do("POST", "/api/settings/cve/sync", ""); code != 409 {
		t.Fatalf("disabled sync: %d", code)
	}
}

func TestCVEFeedEnv(t *testing.T) {
	t.Setenv("ARTEX_CVE_FEED_DIR", " /feed ")
	t.Setenv("ARTEX_NVD_API_KEY", "k")
	t.Setenv("ARTEX_CVE_SYNC_INTERVAL", "30m")
	f := newCVEFeedFromEnv()
	if f.dir != "/feed" || f.apiKey != "k" || f.interval != 0 {
		t.Errorf("feed %+v (an interval under 1h must be refused)", f)
	}
	t.Setenv("ARTEX_CVE_SYNC_INTERVAL", "24h")
	if f := newCVEFeedFromEnv(); f.interval != 24*time.Hour {
		t.Errorf("interval %v", f.interval)
	}
}

func TestCVEFeedSyncRunningUntilReloaded(t *testing.T) {
	rec := &installRecorder{}
	f := testFeed(copyTestFeed(t), rec)
	f.syncFn = func(context.Context, nvdsync.Options) (nvdsync.Stats, error) {
		return nvdsync.Stats{Mode: "full", Written: 7}, nil
	}
	if err := f.startSync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	// Poll as fast as possible: the first status that says the sync finished must
	// already show the feed it loaded, never the empty one it replaced.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := f.status()
		if st["sync"].(map[string]any)["running"] == false {
			if st["active"] != true || st["loaded"].(cvematch.LoadStats).CVEs == 0 {
				t.Fatalf("finished sync shown next to the unloaded feed: %v", st)
			}
			return
		}
	}
	t.Fatal("the sync never finished")
}

func TestCVEFeedFailedAttemptKeepsLastSuccess(t *testing.T) {
	rec := &installRecorder{}
	f := testFeed(copyTestFeed(t), rec)
	clock := time.Date(2026, 1, 5, 3, 0, 0, 0, time.UTC)
	f.now = func() time.Time { return clock }
	f.syncFn = func(context.Context, nvdsync.Options) (nvdsync.Stats, error) {
		return nvdsync.Stats{Mode: "full", Written: 250000}, nil
	}
	if err := f.startSync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return f.status()["sync"].(map[string]any)["running"] == false })
	clock = clock.Add(24 * time.Hour)
	f.syncFn = func(context.Context, nvdsync.Options) (nvdsync.Stats, error) {
		return nvdsync.Stats{}, errors.New("NVD answered 503")
	}
	if err := f.startSync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return f.status()["sync"].(map[string]any)["last_error"] != "" })
	s := f.status()["sync"].(map[string]any)
	if s["last_at"] != "2026-01-05T03:00:00Z" || s["last_attempt_at"] != "2026-01-06T03:00:00Z" {
		t.Fatalf("the failed attempt's time was paired with the earlier success: %v", s)
	}
}
