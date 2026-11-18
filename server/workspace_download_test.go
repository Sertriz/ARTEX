package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestWorkspaceDownloadOctetStream: whatever the extension, a workspace file is
// served as application/octet-stream with nosniff, so an agent-written .js,
// .html or .svg file can never load as script or render as markup of the
// console's origin. The bytes and the attachment name are unchanged.
func TestWorkspaceDownloadOctetStream(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	dir := t.TempDir()
	files := []struct{ rel, content, disposition string }{
		{"loot/payload.js", "alert(document.domain)//\n",
			`attachment; filename="payload.js"; filename*=UTF-8''payload.js`},
		{"loot/page.html", "<!doctype html><script>alert(document.cookie)</script>",
			`attachment; filename="page.html"; filename*=UTF-8''page.html`},
		{"loot/rapport é.svg", `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
			`attachment; filename="rapport é.svg"; filename*=UTF-8''rapport%20%C3%A9.svg`},
		{"notes", "no extension, sniffs as text",
			`attachment; filename="notes"; filename*=UTF-8''notes`},
	}
	for _, f := range files {
		writeFile(t, dir, f.rel, f.content)
	}
	s := &Server{jwtKey: key, m: &Manager{dir: dir}}
	h := s.Handler()
	tok := headerTestToken(t, key)

	get := func(rel, rangeHdr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/workspace/download?path="+url.QueryEscape(rel), nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		if rangeHdr != "" {
			req.Header.Set("Range", rangeHdr)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for _, f := range files {
		t.Run(f.rel, func(t *testing.T) {
			rec := get(f.rel, "")
			if rec.Code != 200 {
				t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
			}
			checkHeaders(t, rec.Header(), map[string]string{
				"Content-Type":            "application/octet-stream",
				"X-Content-Type-Options":  "nosniff",
				"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; sandbox",
				"Cache-Control":           "no-store",
			})
			if got := rec.Body.String(); got != f.content {
				t.Errorf("body = %q, want %q", got, f.content)
			}
			if got := rec.Header().Get("Content-Disposition"); got != f.disposition {
				t.Errorf("Content-Disposition = %q, want %q", got, f.disposition)
			}
		})
	}

	// Ranges still work and keep the type (a resumed download).
	rec := get("loot/payload.js", "bytes=0-4")
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "alert" {
		t.Fatalf("range: status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("range: Content-Type = %q, want application/octet-stream", got)
	}

	// Unchanged error paths, which still carry the API headers.
	for _, c := range []struct {
		rel  string
		code int
	}{{"loot", 404}, {"missing.js", 404}, {"../../etc/passwd", 404}} {
		rec := get(c.rel, "")
		if rec.Code != c.code {
			t.Errorf("%s: status = %d, want %d", c.rel, rec.Code, c.code)
		}
		checkHeaders(t, rec.Header(), wantAPIHeaders)
	}
}
