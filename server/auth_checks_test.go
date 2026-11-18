package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var testJWTKey = []byte("0123456789abcdef0123456789abcdef")

// mintToken signs claims with method and key, for tokens issueSessionToken
// would never produce.
func mintToken(t *testing.T, method jwt.SigningMethod, key any, claims jwt.Claims) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// handMint builds a token from raw header and payload JSON with an HS256
// signature over them, the way scripts/benchmark/run_bench.py mints one.
func handMint(header, payload string, key []byte) string {
	b64 := base64.RawURLEncoding.EncodeToString
	signing := b64([]byte(header)) + "." + b64([]byte(payload))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signing))
	return signing + "." + b64(mac.Sum(nil))
}

// b64URLAlphabet is the base64url alphabet, in value order.
const b64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// trailingBitVariants are tok with the two unused low bits of its last
// signature character set: a 32-byte HS256 signature is 43 base64url
// characters, 258 bits, and a lax decoder ignores the last two.
func trailingBitVariants(t *testing.T, tok string) []string {
	t.Helper()
	sig := tok[strings.LastIndexByte(tok, '.')+1:]
	idx := strings.IndexByte(b64URLAlphabet, tok[len(tok)-1])
	if len(sig) != 43 || idx < 0 || idx&3 != 0 {
		t.Fatalf("unexpected signature %q", sig)
	}
	var out []string
	for b := 1; b < 4; b++ {
		out = append(out, tok[:len(tok)-1]+string(b64URLAlphabet[idx|b]))
	}
	return out
}

// whitespaceVariants are tok with CR or LF inside or before its signature,
// which the base64 decoder skips.
func whitespaceVariants(tok string) map[string]string {
	dot := strings.LastIndexByte(tok, '.') + 1
	return map[string]string{
		"LF in the signature":       tok[:dot+10] + "\n" + tok[dot+10:],
		"CRLF before the signature": tok[:dot] + "\r\n" + tok[dot:],
		"CRLF x3 in the signature":  tok[:dot+5] + "\r\n\r\n\r\n" + tok[dot+5:],
		"CR at the end":             tok + "\r",
	}
}

func TestParseToken(t *testing.T) {
	now := time.Now()
	exp := jwt.NewNumericDate(now.Add(time.Hour))
	valid := jwt.RegisteredClaims{Subject: "ARTEX", ExpiresAt: exp, IssuedAt: jwt.NewNumericDate(now)}
	padded := func(n int) jwt.MapClaims {
		return jwt.MapClaims{"sub": "ARTEX", "exp": exp.Unix(), "pad": strings.Repeat("a", n)}
	}
	issued, err := (&Server{jwtKey: testJWTKey}).issueSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	good := mintToken(t, jwt.SigningMethodHS256, testJWTKey, valid)
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
	payload := fmt.Sprintf(`{"sub":"ARTEX","iat":%d,"exp":%d}`, now.Unix(), now.Add(7*24*time.Hour).Unix())

	// Other spellings of good. Each verifies under a parser without strict
	// decoding when the canonical-form check is skipped, so each would be the
	// same token under another change-password limiter key.
	malleable := map[string]string{}
	for i, v := range trailingBitVariants(t, good) {
		malleable[fmt.Sprintf("signature trailing bits %d", i+1)] = v
	}
	for name, v := range whitespaceVariants(good) {
		malleable[name] = v
	}
	lax := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithSubject(tokenSubject))
	for name, v := range malleable {
		if _, err := lax.Parse(v, func(*jwt.Token) (any, error) { return testJWTKey, nil }); err != nil {
			t.Fatalf("%s: a lax parser rejects it (%v); the case tests nothing", name, err)
		}
		t.Run(name, func(t *testing.T) {
			if claims, err := parseToken(v, testJWTKey); !errors.Is(err, errInvalidToken) {
				t.Fatalf("parseToken = %+v, %v; want errInvalidToken", claims, err)
			}
		})
	}

	for _, tc := range []struct {
		name  string
		token string
		ok    bool
	}{
		{"issued session token", issued, true},
		{"HS256 with exp and sub", good, true},
		{"benchmark-shaped {sub,iat,exp}", handMint(`{"alg":"HS256","typ":"JWT"}`, payload, testJWTKey), true},
		{"just under the size cap", mintToken(t, jwt.SigningMethodHS256, testJWTKey, padded(2800)), true},

		{"empty", "", false},
		{"garbage", "not-a-token", false},
		{"HS384", mintToken(t, jwt.SigningMethodHS384, testJWTKey, valid), false},
		{"HS512", mintToken(t, jwt.SigningMethodHS512, testJWTKey, valid), false},
		{"alg none", mintToken(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, valid), false},
		{"RS256 header over an HMAC signature", handMint(`{"alg":"RS256","typ":"JWT"}`, payload, testJWTKey), false},
		{"missing exp", mintToken(t, jwt.SigningMethodHS256, testJWTKey, jwt.RegisteredClaims{Subject: "ARTEX"}), false},
		{"missing sub", mintToken(t, jwt.SigningMethodHS256, testJWTKey, jwt.RegisteredClaims{ExpiresAt: exp}), false},
		{"wrong sub", mintToken(t, jwt.SigningMethodHS256, testJWTKey, jwt.RegisteredClaims{Subject: "admin", ExpiresAt: exp}), false},
		{"expired", mintToken(t, jwt.SigningMethodHS256, testJWTKey, jwt.RegisteredClaims{Subject: "ARTEX", ExpiresAt: jwt.NewNumericDate(now.Add(-time.Minute))}), false},
		{"not valid yet", mintToken(t, jwt.SigningMethodHS256, testJWTKey, jwt.RegisteredClaims{Subject: "ARTEX", ExpiresAt: exp, NotBefore: jwt.NewNumericDate(now.Add(time.Hour))}), false},
		{"other key", mintToken(t, jwt.SigningMethodHS256, []byte("another key, another key, another"), valid), false},
		{"tampered signature", tampered, false},
		{"padded signature", good + "=", false},
		{"trailing space", good + " ", false},
		{"leading dot", "." + good, false},
		{"empty payload", parts[0] + ".." + parts[2], false},
		{"four segments", good + ".AAAA", false},
		{"over 4 KiB", mintToken(t, jwt.SigningMethodHS256, testJWTKey, padded(4096)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := parseToken(tc.token, testJWTKey)
			if tc.ok {
				if err != nil || claims.Subject != "ARTEX" {
					t.Fatalf("parseToken = %+v, %v; want sub ARTEX", claims, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseToken accepted it: %+v", claims)
			}
			if !errors.Is(err, errInvalidToken) && !errors.Is(err, errNoToken) {
				t.Fatalf("err = %v; want errInvalidToken or errNoToken", err)
			}
		})
	}
	if n := len(mintToken(t, jwt.SigningMethodHS256, testJWTKey, padded(2800))); n > maxTokenBytes {
		t.Fatalf("the under-the-cap case is %d bytes; it must stay under %d", n, maxTokenBytes)
	}
}

func bearer(r *http.Request, token string) *http.Request {
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestAuthExemptions(t *testing.T) {
	s := &Server{jwtKey: testJWTKey}
	tok, err := s.issueSessionToken()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("requireAuth", func(t *testing.T) {
		var got authInfo
		var gotOK bool
		h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, gotOK = r.Context().Value(authInfoKey{}).(authInfo)
			w.WriteHeader(200)
		}))
		serve := func(r *http.Request) int {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w.Code
		}
		for _, p := range []string{"/api/auth/status", "/api/auth/init", "/api/auth/login", "/api/health"} {
			if code := serve(httptest.NewRequest("GET", p, nil)); code != 200 {
				t.Fatalf("%s without a token: %d, want 200 (exempt)", p, code)
			}
		}
		for _, p := range []string{
			"/api/auth/change-password", "/api/auth/foo", "/api/auth/", "/api/auth",
			"/api/auth/../tasks", "/api/auth/status/x", "/api/healthz", "/api/health/", "/api/tasks",
		} {
			if code := serve(httptest.NewRequest("GET", p, nil)); code != 401 {
				t.Fatalf("%s without a token: %d, want 401", p, code)
			}
		}
		if code := serve(bearer(httptest.NewRequest("GET", "/api/tasks", nil), tok)); code != 200 {
			t.Fatalf("valid token: %d, want 200", code)
		}
		if !gotOK || got.raw != tok || got.subject != "ARTEX" {
			t.Fatalf("request context authInfo = %+v (%v), want the token and sub ARTEX", got, gotOK)
		}
		hs384 := mintToken(t, jwt.SigningMethodHS384, testJWTKey, jwt.RegisteredClaims{Subject: "ARTEX", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))})
		if code := serve(bearer(httptest.NewRequest("GET", "/api/tasks", nil), hs384)); code != 401 {
			t.Fatalf("HS384 token: %d, want 401", code)
		}
		// Only the canonical spelling of a token is accepted: other
		// spellings would be other limiter keys for the same token.
		for _, v := range trailingBitVariants(t, tok) {
			if code := serve(bearer(httptest.NewRequest("GET", "/api/tasks", nil), v)); code != 401 {
				t.Fatalf("Bearer %q (trailing bits): %d, want 401", v, code)
			}
		}
		for name, v := range whitespaceVariants(tok) {
			r := httptest.NewRequest("GET", "/api/tasks?"+url.Values{"token": {v}}.Encode(), nil)
			if code := serve(r); code != 401 {
				t.Fatalf("?token= with %s: %d, want 401", name, code)
			}
		}
		if code := serve(httptest.NewRequest("GET", "/api/tasks?"+url.Values{"token": {tok}}.Encode(), nil)); code != 200 {
			t.Fatalf("?token= with the token itself: %d, want 200", code)
		}
	})

	// Through Handler(): the root mux redirects dot segments and double
	// slashes before requireAuth runs; an encoded %2e%2e reaches it decoded and
	// matches no exemption.
	t.Run("Handler", func(t *testing.T) {
		h := s.Handler()
		for _, tc := range []struct {
			target string
			code   int
		}{
			{"/api/auth/../tasks", 307},
			{"/api/./auth/login", 307},
			{"//api/tasks", 307},
			{"/api/auth/%2e%2e/tasks", 401},
			{"/api/auth/%2e%2e/health", 401},
			{"/api/auth/%2E%2E/tasks", 401},
		} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", tc.target, nil))
			if w.Code != tc.code {
				t.Fatalf("GET %s: %d, want %d; body=%s", tc.target, w.Code, tc.code, w.Body.String())
			}
		}
		// change-password is no longer exempt: without a token requireAuth
		// answers before the handler (which would need a Manager) runs.
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatalf("change-password without a token: %d, want 401", w.Code)
		}
		// health stays public.
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/health", nil))
		if w.Code != 200 {
			t.Fatalf("health without a token: %d, want 200", w.Code)
		}
	})
}

func TestCORSOnlyOnSSE(t *testing.T) {
	h := (&Server{jwtKey: testJWTKey}).Handler()
	do := func(method, target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		r.Header.Set("Origin", "http://192.0.2.5:3000")
		r.Header.Set("Access-Control-Request-Method", "GET")
		r.Header.Set("Access-Control-Request-Headers", "authorization, last-event-id")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if v := w.Header().Get("Access-Control-Allow-Credentials"); v != "" {
			t.Fatalf("%s %s: Access-Control-Allow-Credentials=%q, want none", method, target, v)
		}
		return w
	}

	for _, p := range []string{"/api/logs/stream", "/api/exploration/activity/stream", "/api/side-questions/sq-123/events"} {
		w := do("OPTIONS", p)
		if w.Code != 204 {
			t.Fatalf("OPTIONS %s: %d, want 204", p, w.Code)
		}
		hdr := w.Header()
		if hdr.Get("Access-Control-Allow-Origin") != "*" || hdr.Get("Access-Control-Max-Age") != "600" {
			t.Fatalf("OPTIONS %s: headers %v", p, hdr)
		}
		allowed := strings.ToLower(hdr.Get("Access-Control-Allow-Headers"))
		for _, want := range []string{"authorization", "content-type", "last-event-id"} {
			if !strings.Contains(allowed, want) {
				t.Fatalf("OPTIONS %s: Allow-Headers %q lacks %s", p, allowed, want)
			}
		}
		// The stream itself still needs a token, and the 401 stays readable.
		w = do("GET", p+"?since=0")
		if w.Code != 401 || w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("GET %s without a token: %d ACAO=%q, want 401 with ACAO *", p, w.Code, w.Header().Get("Access-Control-Allow-Origin"))
		}
	}

	for _, tc := range []struct {
		method, target string
		code           int
	}{
		{"OPTIONS", "/api/auth/login", 405}, // exempt, so the mux answers: no POST-only preflight
		{"OPTIONS", "/api/auth/change-password", 401},
		{"OPTIONS", "/api/tasks", 401},
		{"OPTIONS", "/api/tools/custom/test", 401},
		{"OPTIONS", "/api/traffic/stream", 401},
		{"OPTIONS", "/api/side-questions/a/b/events", 401},
		{"OPTIONS", "/api/side-questions/a%2Fb/events", 401},
		{"OPTIONS", "/api/side-questions//events", 307}, // the root mux cleans the path first
		{"OPTIONS", "/api/logs/stream/x", 401},
		{"GET", "/api/health", 200},
		{"GET", "/api/tasks", 401},
	} {
		w := do(tc.method, tc.target)
		if w.Code != tc.code {
			t.Fatalf("%s %s: %d, want %d", tc.method, tc.target, w.Code, tc.code)
		}
		if v := w.Header().Get("Access-Control-Allow-Origin"); v != "" {
			t.Fatalf("%s %s: Access-Control-Allow-Origin=%q, want none outside the SSE streams", tc.method, tc.target, v)
		}
	}
}

// hashedKey is the form of every change-password limiter key.
var hashedKey = regexp.MustCompile(`^tok:[0-9a-f]{64}$`)

// pwStore stands in for the settings table in change-password tests.
type pwStore struct {
	hash   string
	getErr error
	reads  int
}

func (p *pwStore) get(key string) (string, bool, error) {
	p.reads++
	if p.getErr != nil {
		return "", false, p.getErr
	}
	if key != authPassKey {
		return "", false, nil
	}
	return p.hash, p.hash != "", nil
}

func (p *pwStore) set(key, value string) error {
	if key == authPassKey {
		p.hash = value
	}
	return nil
}

func TestChangePassword(t *testing.T) {
	const newPassword = "a new password, long enough"
	hash, err := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	clk := newFakeClock()
	store := &pwStore{hash: string(hash)}
	s := &Server{jwtKey: testJWTKey, loginLimit: newLoginLimiter(clk.now), pwLimit: newLoginLimiter(clk.now)}
	tok, err := s.issueSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	// A second token: other claims, so another string and another bucket.
	other, err := signToken(testJWTKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const remote = "192.0.2.30:40000"
	send := func(target, token, oldPw, newPw string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"old_password":%q,"new_password":%q}`, oldPw, newPw)
		r := httptest.NewRequest("POST", target, strings.NewReader(body))
		r.RemoteAddr = remote
		if token != "" {
			bearer(r, token)
		}
		w := httptest.NewRecorder()
		s.changePassword(w, r, store.get, store.set)
		return w
	}
	change := func(token, oldPw, newPw string) *httptest.ResponseRecorder {
		return send("/api/auth/change-password", token, oldPw, newPw)
	}
	// changeQuery sends the token as ?token=, where CR and LF survive.
	changeQuery := func(token, oldPw, newPw string) *httptest.ResponseRecorder {
		return send("/api/auth/change-password?"+url.Values{"token": {token}}.Encode(), "", oldPw, newPw)
	}
	// limiterKeys checks that every s.pwLimit key is a hash, never a token,
	// and returns the keys.
	limiterKeys := func() map[string]bool {
		t.Helper()
		keys := map[string]bool{}
		for k := range s.pwLimit.entries {
			if !hashedKey.MatchString(k) || strings.Contains(k, tok) || strings.Contains(k, other) {
				t.Fatalf("limiter key %q is not tok:<sha256 hex>", k)
			}
			keys[k] = true
		}
		return keys
	}
	login := func(password string) int {
		r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(fmt.Sprintf(`{"username":"ARTEX","password":%q}`, password)))
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		s.login(w, r, store.get)
		return w.Code
	}
	errorOf := func(w *httptest.ResponseRecorder) string {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return body.Error
	}

	if w := change("", oldPassword, newPassword); w.Code != 401 {
		t.Fatalf("no token: %d, want 401", w.Code)
	}

	// A wrong current password is 403: a 401 would sign the browser out.
	w := change(tok, "wrong-password", newPassword)
	if w.Code != 403 || errorOf(w) != "Current password is wrong" {
		t.Fatalf("wrong current password: %d %s, want 403", w.Code, w.Body.String())
	}
	if w := change(tok, oldPassword, "short"); w.Code != 400 {
		t.Fatalf("short new password: %d, want 400", w.Code)
	}

	// Every attempt counts against the token, whatever its outcome: two so far.
	for i := 2; i < loginMaxAttempts; i++ {
		if w := change(tok, "wrong-password", newPassword); w.Code != 403 {
			t.Fatalf("attempt %d: %d, want 403", i+1, w.Code)
		}
	}
	w = change(tok, oldPassword, newPassword) // even the right password is refused while blocked
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" || !strings.Contains(errorOf(w), "60 seconds") {
		t.Fatalf("over the limit: %d Retry-After=%q %s, want 429 with Retry-After 60", w.Code, w.Header().Get("Retry-After"), w.Body.String())
	}
	if store.hash != string(hash) {
		t.Fatal("a refused attempt changed the password")
	}
	if keys := limiterKeys(); len(keys) != 1 || !keys[passwordLimitKey(tok)] {
		t.Fatalf("limiter keys = %v, want only the token's", keys)
	}

	// Another spelling of the blocked token is not a fresh budget: it is
	// refused before the limiter, the right password included, and the
	// token stays blocked.
	variants := trailingBitVariants(t, tok)
	for _, v := range variants {
		if w := change(v, oldPassword, newPassword); w.Code != 401 {
			t.Fatalf("Bearer variant %q: %d %s, want 401", v, w.Code, w.Body.String())
		}
	}
	for name, v := range whitespaceVariants(tok) {
		if w := changeQuery(v, oldPassword, newPassword); w.Code != 401 {
			t.Fatalf("?token= with %s: %d %s, want 401", name, w.Code, w.Body.String())
		}
	}
	if store.hash != string(hash) {
		t.Fatal("a token variant changed the password")
	}
	if keys := limiterKeys(); len(keys) != 1 {
		t.Fatalf("limiter keys = %v after the variants, want only the token's", keys)
	}
	if w := changeQuery(tok, oldPassword, newPassword); w.Code != 429 {
		t.Fatalf("the token itself as ?token= after the variants: %d, want 429 (still blocked)", w.Code)
	}

	// The bucket is the token's: another token, and login from the same IP, are not blocked.
	if w := change(other, "wrong-password", newPassword); w.Code != 403 {
		t.Fatalf("other token: %d, want 403", w.Code)
	}
	if code := login(oldPassword); code != 200 {
		t.Fatalf("login from the same IP: %d, want 200 (separate limiter)", code)
	}
	// Nor does a failed login count against change-password.
	if code := login("wrong-password"); code != 401 {
		t.Fatalf("failed login: %d, want 401", code)
	}

	// A store read error is 503, after the limiter.
	clk.advance(loginMaxBlock)
	store.getErr = errors.New("connection refused")
	if w := change(other, oldPassword, newPassword); w.Code != 503 {
		t.Fatalf("store read error: %d, want 503", w.Code)
	}
	store.getErr = nil

	// Success: 200 {ok:true}, no token in the reply, the new hash stored, the
	// token's bucket cleared.
	w = change(tok, oldPassword, newPassword)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"ok":true}` {
		t.Fatalf("right password: %d %s, want 200 {\"ok\":true}", w.Code, w.Body.String())
	}
	if bcrypt.CompareHashAndPassword([]byte(store.hash), []byte(newPassword)) != nil {
		t.Fatal("the new password was not stored")
	}
	// The token's entry is gone; the other token's, from its 403 and 503,
	// is all that is left, and it is a hash.
	if keys := limiterKeys(); len(keys) != 1 || !keys[passwordLimitKey(other)] {
		t.Fatalf("limiter keys after the change = %v, want only the other token's", keys)
	}
	for i := 0; i < loginMaxAttempts; i++ {
		if w := change(tok, "wrong-password", oldPassword+"-again"); w.Code != 403 {
			t.Fatalf("after the reset, attempt %d: %d, want 403 (a full budget)", i+1, w.Code)
		}
	}
	if w := change(tok, "wrong-password", oldPassword+"-again"); w.Code != 429 {
		t.Fatalf("after the reset, attempt %d: %d, want 429", loginMaxAttempts+1, w.Code)
	}

	// Behind requireAuth the handler uses the verified token from the context
	// and is never reached without one.
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.changePassword(w, r, store.get, store.set)
	}))
	reads := store.reads
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(`{}`)))
	if w.Code != 401 || store.reads != reads {
		t.Fatalf("no token through requireAuth: %d, %d reads; want 401 and no read", w.Code, store.reads-reads)
	}
	w = httptest.NewRecorder()
	body := fmt.Sprintf(`{"old_password":%q,"new_password":%q}`, "wrong-password", oldPassword+"-again")
	h.ServeHTTP(w, bearer(httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(body)), other))
	if w.Code != 403 {
		t.Fatalf("through requireAuth with a token: %d, want 403", w.Code)
	}
}

func TestLoginLimiterNilSafe(t *testing.T) {
	var l *loginLimiter
	if wait := l.allow("192.0.2.1"); wait != 0 {
		t.Fatalf("nil limiter allow = %v, want 0", wait)
	}
	l.reset("192.0.2.1")
}

func TestApproverUsesVerifiedToken(t *testing.T) {
	s := &Server{jwtKey: testJWTKey}
	tok, err := s.issueSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	// requireAuth's authInfo wins: the token is not parsed again.
	r := httptest.NewRequest("POST", "/api/intercept/pending/1/decide", nil)
	r = r.WithContext(context.WithValue(r.Context(), authInfoKey{}, authInfo{raw: "x", subject: "from-context"}))
	if got := s.approver(r); got != "from-context" {
		t.Fatalf("approver with a context = %q, want from-context", got)
	}
	// Called directly (as some tests do), the request's token is verified.
	if got := s.approver(bearer(httptest.NewRequest("POST", "/", nil), tok)); got != "ARTEX" {
		t.Fatalf("approver with a valid token = %q, want ARTEX", got)
	}
	for name, bad := range map[string]string{
		"none":      "",
		"other key": mintToken(t, jwt.SigningMethodHS256, []byte("another key, another key, another"), jwt.RegisteredClaims{Subject: "ARTEX", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}),
		"HS512":     mintToken(t, jwt.SigningMethodHS512, testJWTKey, jwt.RegisteredClaims{Subject: "ARTEX", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}),
		"no exp":    mintToken(t, jwt.SigningMethodHS256, testJWTKey, jwt.RegisteredClaims{Subject: "ARTEX"}),
	} {
		r := httptest.NewRequest("POST", "/", nil)
		if bad != "" {
			bearer(r, bad)
		}
		if got := s.approver(r); got != "" {
			t.Fatalf("approver with %s = %q, want none", name, got)
		}
	}
}

// The route through Handler() and PostgreSQL: change-password needs a token,
// answers 403 to a wrong current password and stores the new one. The stored
// password is restored afterwards.
func TestChangePasswordThroughHandler(t *testing.T) {
	skipWithoutDSN(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	prev, hadPrev, err := m.pg.GetSetting(authPassKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadPrev {
			_ = m.pg.SetSetting(authPassKey, prev)
		} else {
			_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey)
		}
	})
	const current, next = "the current password", "the next password, long enough"
	hash, err := bcrypt.GenerateFromPassword([]byte(current), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	// A nil limiter allows everything, so a New() that forgot one would turn
	// the brute-force limit off without any other test failing.
	if s.loginLimit == nil || s.pwLimit == nil {
		t.Fatal("New() left a limiter unset: login or change-password would be unlimited")
	}
	if s.loginLimit == s.pwLimit {
		t.Fatal("New() shares one limiter between login and change-password")
	}
	h := s.Handler()
	post := func(path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			bearer(r, token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	loginToken := func(password string) (int, string) {
		w := post("/api/auth/login", "", fmt.Sprintf(`{"username":"ARTEX","password":%q}`, password))
		var out struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out.Token
	}

	code, tok := loginToken(current)
	if code != 200 || tok == "" {
		t.Fatalf("login: %d, want 200 with a token", code)
	}
	body := func(oldPw, newPw string) string {
		return fmt.Sprintf(`{"old_password":%q,"new_password":%q}`, oldPw, newPw)
	}
	if w := post("/api/auth/change-password", "", body(current, next)); w.Code != 401 {
		t.Fatalf("no token: %d, want 401", w.Code)
	}
	if w := post("/api/auth/change-password", tok, body("wrong-password", next)); w.Code != 403 {
		t.Fatalf("wrong current password: %d %s, want 403", w.Code, w.Body.String())
	}
	if w := post("/api/auth/change-password", tok, body(current, next)); w.Code != 200 {
		t.Fatalf("right current password: %d %s, want 200", w.Code, w.Body.String())
	}
	if code, _ := loginToken(current); code != 401 {
		t.Fatalf("login with the old password: %d, want 401", code)
	}
	code, tok = loginToken(next)
	if code != 200 || tok == "" {
		t.Fatalf("login with the new password: %d, want 200 with a token", code)
	}

	// Both limits are live through New() and Handler(). Every attempt counts
	// before the body is read, so empty bodies (400, no bcrypt) use them up.
	blocked := func(what string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != 429 || w.Header().Get("Retry-After") == "" {
			t.Fatalf("%s attempt %d: %d Retry-After=%q, want 429 with Retry-After", what, loginMaxAttempts+1, w.Code, w.Header().Get("Retry-After"))
		}
	}
	for i := 0; i < loginMaxAttempts; i++ {
		if w := post("/api/auth/change-password", tok, `{}`); w.Code != 400 {
			t.Fatalf("change-password attempt %d with an empty body: %d, want 400", i+1, w.Code)
		}
	}
	blocked("change-password", post("/api/auth/change-password", tok, body(next, current)))
	for i := 0; i < loginMaxAttempts; i++ {
		if w := post("/api/auth/login", "", `{"username":"nobody","password":"x"}`); w.Code != 401 {
			t.Fatalf("login attempt %d as another user: %d, want 401", i+1, w.Code)
		}
	}
	w := post("/api/auth/login", "", fmt.Sprintf(`{"username":"ARTEX","password":%q}`, next))
	blocked("login", w)
}
