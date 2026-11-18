package server

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// newWebUIHandler serves the statically exported frontend in root. Public (no
// JWT): auth is enforced client-side and on /api. It serves the exported
// per-route index.html files and falls back to index.html so client-side routing
// still resolves unknown paths.
//
// It is untagged so the default build compiles and tests it; webui_embed.go
// (-tags embedui) only hands it the embedded FS.
func newWebUIHandler(root fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		// 1) exact file (assets: _next/*, favicon.ico, ...)
		// 2) route dir → <p>/index.html (trailingSlash export)
		// 3) <p>.html
		// 4) SPA fallback → index.html (hand it to client-side routing)
		for _, cand := range []string{p, p + "/index.html", p + ".html"} {
			if serveFileIfExists(w, r, root, cand) {
				return
			}
		}
		http.ServeFileFS(w, r, root, "index.html")
	})
}

// serveFileIfExists serves name from fsys when it exists as a regular file.
func serveFileIfExists(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) bool {
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	st, statErr := f.Stat()
	_ = f.Close()
	if statErr != nil || st.IsDir() {
		return false
	}
	http.ServeFileFS(w, r, fsys, name)
	return true
}
