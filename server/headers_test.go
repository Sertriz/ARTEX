package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The expected values are spelled out here rather than taken from headers.go,
// so a change to a constant fails the test.
var (
	wantAPIHeaders = map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "same-origin",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; sandbox",
		"Cache-Control":           "no-store",
	}
	wantUIHeaders = map[string]string{
		"X-Content-Type-Options":     "nosniff",
		"X-Frame-Options":            "DENY",
		"Referrer-Policy":            "same-origin",
		"Permissions-Policy":         "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
)

// checkHeaders asserts that each wanted header has exactly that one value, and
// that each header in absent is not set at all.
func checkHeaders(t *testing.T, got http.Header, want map[string]string, absent ...string) {
	t.Helper()
	for k, v := range want {
		if vals := got.Values(k); len(vals) != 1 || vals[0] != v {
			t.Errorf("%s = %q, want exactly %q", k, vals, v)
		}
	}
	for _, k := range absent {
		if vals := got.Values(k); len(vals) != 0 {
			t.Errorf("%s = %q, want it unset", k, vals)
		}
	}
}

// headerTestToken returns a console session token for key with the claims every
// verifier accepts (HS256, subject ARTEX, an expiry). It is spelled out rather
// than taken from the server's signing helper so these tests do not depend on
// that helper's name, which the auth work changes.
func headerTestToken(t *testing.T, key []byte) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "ARTEX",
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// The UI must not get the API's sandbox CSP or no-store: the static assets stay
// cacheable, and the UI's own CSP is a separate, per-page policy.
var uiAbsent = []string{"Content-Security-Policy", "Cache-Control"}

func TestSecurityHeaders(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	s := &Server{jwtKey: key}
	h := s.Handler()
	tok := headerTestToken(t, key)

	// Through Handler(): the API routes, requireAuth, cors, the mux and, in the
	// default (no embedui) build, the stub UI handler.
	cases := []struct {
		name, method, path, bearer string
		wantCode                   int
		want                       map[string]string
		absent                     []string
	}{
		{"api 200 health", "GET", "/api/health", "", 200, wantAPIHeaders, nil},
		{"api 200 with token", "GET", "/api/health", tok, 200, wantAPIHeaders, nil},
		{"api 401 no token", "GET", "/api/tasks", "", 401, wantAPIHeaders, nil},
		{"api 401 bad token", "GET", "/api/tasks", "not-a-jwt", 401, wantAPIHeaders, nil},
		// An SSE path: its preflight is answered by cors() with 204.
		{"api OPTIONS preflight", "OPTIONS", "/api/logs/stream", "", 204, wantAPIHeaders, nil},
		{"api 404 unknown route", "GET", "/api/no-such-route", tok, 404, wantAPIHeaders, nil},
		{"api 405 wrong method", "DELETE", "/api/health", tok, 405, wantAPIHeaders, nil},
		{"api bare prefix redirect", "GET", "/api", "", 307, wantAPIHeaders, nil},
		{"ui stub root", "GET", "/", "", 404, wantUIHeaders, uiAbsent},
		{"ui stub route", "GET", "/function/tasks/", "", 404, wantUIHeaders, uiAbsent},
		{"ui stub asset", "GET", "/_next/static/chunks/app.js", "", 404, wantUIHeaders, uiAbsent},
		{"apix is not api", "GET", "/apix/tasks", "", 404, wantUIHeaders, uiAbsent},
		// Encoded targets: the root mux routes on the unescaped first segment, so
		// these reach the API handler and must get the API set (isAPIPath uses URL.Path).
		{"api encoded segment", "GET", "/%61pi/health", "", 200, wantAPIHeaders, nil},
		{"api encoded segment 401", "GET", "/%61pi/tasks", "", 401, wantAPIHeaders, nil},
		// Decodes to /api/health but reaches the UI handler: the stricter set is the safe direction.
		{"encoded slash after api", "GET", "/api%2Fhealth", "", 404, wantAPIHeaders, nil},
		{"double slash redirect", "GET", "//api/health", "", 307, wantUIHeaders, uiAbsent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, nil)
			if c.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+c.bearer)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != c.wantCode {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, c.wantCode, rec.Body.String())
			}
			checkHeaders(t, rec.Header(), c.want, c.absent...)
		})
	}

	t.Run("api OPTIONS keeps cors", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("OPTIONS", "/api/logs/stream", nil))
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
		}
	})

	// A real connection: the SSE handler needs a Flusher and runs until the
	// client goes away. Its own Cache-Control: no-cache replaces the default.
	t.Run("api SSE stream keeps its own Cache-Control", func(t *testing.T) {
		srv := httptest.NewServer(h)
		defer srv.Close()
		req, _ := http.NewRequest("GET", srv.URL+"/api/logs/stream?since=0", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			t.Fatalf("status = %d, Content-Type = %q", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		want := map[string]string{}
		for k, v := range wantAPIHeaders {
			want[k] = v
		}
		want["Cache-Control"] = "no-cache"
		checkHeaders(t, resp.Header, want)
	})

	t.Run("handler-set values win", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/cached" {
				w.Header().Set("Cache-Control", "private, max-age=60")
			} else {
				w.Header().Set("Content-Security-Policy", "default-src 'self'")
			}
			w.WriteHeader(200)
		})
		wrapped := securityHeaders(inner)

		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, httptest.NewRequest("GET", "/api/cached", nil))
		want := map[string]string{}
		for k, v := range wantAPIHeaders {
			want[k] = v
		}
		want["Cache-Control"] = "private, max-age=60"
		checkHeaders(t, rec.Header(), want)

		rec = httptest.NewRecorder()
		wrapped.ServeHTTP(rec, httptest.NewRequest("GET", "/function/tasks/", nil))
		want = map[string]string{"Content-Security-Policy": "default-src 'self'"}
		for k, v := range wantUIHeaders {
			want[k] = v
		}
		checkHeaders(t, rec.Header(), want, "Cache-Control")
	})

	// The embedded UI's file serving (newWebUIHandler, untagged) behind the
	// wrapper, as Handler() wires it in an embedui build.
	t.Run("ui embedded", func(t *testing.T) {
		mod := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
		fsys := fstest.MapFS{
			"index.html":                  {Data: []byte("<!doctype html><title>root</title>"), ModTime: mod},
			"function/tasks/index.html":   {Data: []byte("<!doctype html><title>tasks</title>"), ModTime: mod},
			"_next/static/chunks/app.js":  {Data: []byte("console.log(1)"), ModTime: mod},
			"_next/static/css/app.css":    {Data: []byte("body{}"), ModTime: mod},
			"function/tasks/__next.0.txt": {Data: []byte("0:{}"), ModTime: mod},
		}
		ui := securityHeaders(newWebUIHandler(fsys))
		for _, c := range []struct {
			name, path, ims string
			wantCode        int
			wantType        string
			wantBody        string
		}{
			{"page", "/", "", 200, "text/html; charset=utf-8", "<!doctype html><title>root</title>"},
			{"route", "/function/tasks/", "", 200, "text/html; charset=utf-8", "<!doctype html><title>tasks</title>"},
			{"spa fallback", "/no/such/route", "", 200, "text/html; charset=utf-8", "<!doctype html><title>root</title>"},
			{"script asset", "/_next/static/chunks/app.js", "", 200, "text/javascript; charset=utf-8", "console.log(1)"},
			{"style asset", "/_next/static/css/app.css", "", 200, "text/css; charset=utf-8", "body{}"},
			{"rsc payload", "/function/tasks/__next.0.txt", "", 200, "text/plain; charset=utf-8", "0:{}"},
			{"not modified", "/", mod.Format(http.TimeFormat), 304, "", ""},
		} {
			t.Run(c.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", c.path, nil)
				if c.ims != "" {
					req.Header.Set("If-Modified-Since", c.ims)
				}
				rec := httptest.NewRecorder()
				ui.ServeHTTP(rec, req)
				if rec.Code != c.wantCode {
					t.Fatalf("status = %d, want %d", rec.Code, c.wantCode)
				}
				if c.wantType != "" && rec.Header().Get("Content-Type") != c.wantType {
					t.Errorf("Content-Type = %q, want %q", rec.Header().Get("Content-Type"), c.wantType)
				}
				if rec.Body.String() != c.wantBody {
					t.Errorf("body = %q, want %q", rec.Body.String(), c.wantBody)
				}
				checkHeaders(t, rec.Header(), wantUIHeaders, uiAbsent...)
			})
		}
	})
}

// TestSecurityHeadersOnServeFileError covers the one place a handler drops a
// default: http.ServeFile strips Cache-Control from its own error replies. The
// other headers must survive it.
func TestSecurityHeadersOnServeFileError(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	dir := t.TempDir()
	writeFile(t, dir, "small.txt", "0123456789")
	s := &Server{jwtKey: key, m: &Manager{dir: dir}}
	tok := headerTestToken(t, key)
	req := httptest.NewRequest("GET", "/api/workspace/download?path=small.txt", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Range", "bytes=100-200")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want 416", rec.Code)
	}
	want := map[string]string{}
	for k, v := range wantAPIHeaders {
		if k != "Cache-Control" { // removed by net/http's serveError, see headers.go
			want[k] = v
		}
	}
	checkHeaders(t, rec.Header(), want)
	if body := rec.Body.String(); !strings.HasPrefix(body, "invalid range") {
		t.Errorf("body = %q, want net/http's range error", body)
	}
}
