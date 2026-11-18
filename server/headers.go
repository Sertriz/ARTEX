package server

import (
	"net/http"
	"strings"
)

// Security headers for every response of the console port: the /api routes
// (JSON, the SSE streams, downloads, the errors requireAuth and the mux write)
// and everything else (the embedded UI, or the no-embed stub's 404).
//
// They are set before the wrapped handler runs, so a handler that sets one of
// them with Header().Set replaces the default: the SSE streams set
// Cache-Control: no-cache. A handler that used Header().Add would append a
// second value to the default instead; none does. http.ServeFile, ServeFileFS
// and ServeContent drop Cache-Control (with ETag, Last-Modified and
// Content-Encoding) from their own error replies, such as a 416 for a bad Range
// (GODEBUG httpservecontentkeepheaders); those short text errors keep the other
// headers.
//
// There is no Strict-Transport-Security: ARTEX speaks plain HTTP and cannot know
// whether a TLS proxy fronts it, so HSTS belongs at the TLS-terminating proxy
// (README, reverse proxy deployment). UI pages served by `next dev`, the mock
// demo or a web/out copied into another web server's root never pass through
// here and get none of these headers; their /api requests still reach this
// handler and get the API set.
//
// Browsers apply Cross-Origin-Opener-Policy only over HTTPS or on localhost; on
// a plain-HTTP LAN address (ARTEX_BIND_ADDR=0.0.0.0) they ignore it and Chrome
// logs a console error on each page load. The server cannot tell the
// browser-facing scheme behind a TLS proxy, so COOP is always sent.
const (
	// apiCSP is the policy of every /api response. None of them is meant to be
	// rendered as a page: a browser that does render one (a navigated download,
	// stored target bytes) gets no script, no subresource, no framing and an
	// opaque origin, so the bytes never act with the console's origin.
	apiCSP = "default-src 'none'; frame-ancestors 'none'; sandbox"

	// uiPermissionsPolicy turns off powerful features the UI never uses. The
	// clipboard is left alone: the copy buttons call navigator.clipboard.
	uiPermissionsPolicy = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
)

// securityHeaders wraps the root handler returned by Handler().
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		if isAPIPath(r.URL.Path) {
			h.Set("Content-Security-Policy", apiCSP)
			h.Set("Cache-Control", "no-store")
		} else {
			h.Set("Permissions-Policy", uiPermissionsPolicy)
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
		}
		next.ServeHTTP(w, r)
	})
}

// isAPIPath reports whether path gets the /api header set. The root mux routes
// a request to the API handler only when the first segment of its escaped path
// unescapes to "api", and the decoded path then always starts with "/api/", so
// nothing the API handler serves misses the API headers. The reverse can happen
// for odd encodings ("/api%2Fx" decodes to "/api/x" but reaches the UI handler);
// it gets the stricter set, which is the safe direction.
func isAPIPath(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}
