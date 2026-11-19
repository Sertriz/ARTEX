package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/Autumn-27/artex/config"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// The lower bound matches the setup page's frontend validation — validation that
	// lives only in the frontend is as good as none: hitting the API directly bypasses
	// it. The upper bound is bcrypt's hard limit: past 72 bytes GenerateFromPassword returns ErrPasswordTooLong; rejecting early beats a cryptic "password encryption failed".
	// Both apply to new passwords only (init, change-password); login never checks
	// length, so passwords set under the old 8-character minimum still log in.
	minPasswordRunes = 12
	maxPasswordBytes = 72
)

// errDataSourceUnavailable is the uniform reply when a password-related read fails.
// These handlers must never mistake a failed read for "not set": authInit once let an
// unauthenticated request through on a database error, overwriting the admin password.
const errDataSourceUnavailable = "Data source temporarily unavailable, please retry later"

// validatePassword returns an empty string when passing, otherwise a reason ready to show the user.
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("Password must be at least %d characters", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("Password must not exceed %d bytes", maxPasswordBytes)
	}
	return ""
}

// jwtLegacyBaseDir is the second legacy key location (the executable's directory,
// where releases before ARTEX_JWT_KEY_DIR wrote the key). A var so tests can point it
// at a temp dir.
var jwtLegacyBaseDir = config.BaseDir

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// ARTEX_JWT_KEY_DIR (the /app/keys volume in Docker) or the project base dir, NOT
// the browsable workspace root (dataDir) — the signing key must never be
// listable/downloadable via the file manager. When keyDir/jwt.key is missing, a key
// at dataDir/jwt.key, then at BaseDir()/jwt.key, is migrated (key preserved, so
// sessions stay valid) and the old file removed. Otherwise a random key is
// generated. An existing key file is never overwritten.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("create jwt key dir: %w", err)
	}
	path := filepath.Join(keyDir, jwtKeyFilename)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := migrateJWTKey(path, dataDir); err != nil {
			return nil, err
		}
	}
	data, err := os.ReadFile(path)
	if err == nil {
		key := strings.TrimSpace(string(data))
		if len(key) < 32 {
			return nil, fmt.Errorf("jwt key %s is shorter than 32 bytes; fix or remove it (it is never overwritten)", path)
		}
		return []byte(key), nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read jwt key: %w", err)
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := writeNewJWTKey(path, buf); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] new JWT key written to %s", path)
	return buf, nil
}

// migrateJWTKey copies the first legacy key found (dataDir, then BaseDir) to dst
// and removes the old file. Candidates equal to dst are skipped.
func migrateJWTKey(dst, dataDir string) error {
	for _, src := range []string{
		filepath.Join(dataDir, jwtKeyFilename),
		filepath.Join(jwtLegacyBaseDir(), jwtKeyFilename),
	} {
		if samePath(src, dst) {
			continue
		}
		data, err := os.ReadFile(src)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			log.Printf("[auth] cannot read legacy JWT key %s: %v", src, err)
			continue
		}
		if err := writeNewJWTKey(dst, data); err != nil {
			return fmt.Errorf("migrate jwt key from %s: %w", src, err)
		}
		if err := os.Remove(src); err != nil {
			log.Printf("[auth] JWT key copied to %s but the old file %s could not be removed: %v", dst, src, err)
		}
		log.Printf("[auth] JWT key migrated from %s to %s", src, dst)
		return nil
	}
	return nil
}

// writeNewJWTKey creates path with mode 0600, failing if it already exists.
func writeNewJWTKey(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func samePath(a, b string) bool {
	if absA, err := filepath.Abs(a); err == nil {
		a = absA
	}
	if absB, err := filepath.Abs(b); err == nil {
		b = absB
	}
	return a == b
}

// tokenSubject is the only subject a console token carries: ARTEX has one
// account.
const tokenSubject = "ARTEX"

// maxTokenBytes caps the token a request may present. A session token is
// about 160 bytes; anything far larger is refused before it is parsed.
const maxTokenBytes = 4 << 10

// tokenParser is the only way a console token is verified. It accepts HS256
// alone (no other HMAC size, no "none", no asymmetric algorithm keyed with the
// HMAC secret), requires an exp claim and requires sub to be ARTEX. The library
// rejects an expired or not-yet-valid token on its own. Strict decoding
// refuses a last base64url character with non-zero unused bits, which would
// otherwise give every token three more spellings that verify.
var tokenParser = jwt.NewParser(
	jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	jwt.WithExpirationRequired(),
	jwt.WithSubject(tokenSubject),
	jwt.WithStrictDecoding(),
)

// canonicalToken reports whether raw is exactly three non-empty base64url
// segments separated by dots. The base64 decoder skips CR and LF even in strict
// mode, and the signature is checked over the raw header and payload text
// only, so without this check many strings would verify as one token, and each
// would get its own change-password limiter key.
func canonicalToken(raw string) bool {
	dots := 0
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '.':
			if i == 0 || raw[i-1] == '.' {
				return false
			}
			dots++
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return dots == 2 && raw[len(raw)-1] != '.'
}

var (
	errNoToken      = errors.New("no token")
	errInvalidToken = errors.New("token is invalid or expired")
)

// authInfo is what a verified request token says about the caller.
type authInfo struct {
	raw     string // the token as presented
	subject string // its sub claim, always tokenSubject
}

// authInfoKey is the request-context key under which requireAuth stores the
// authInfo of an authenticated request.
type authInfoKey struct{}

// signToken issues an HS256 token for ARTEX, signed with key and valid for ttl.
func signToken(key []byte, ttl time.Duration) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   tokenSubject,
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		IssuedAt:  jwt.NewNumericDate(now),
	}).SignedString(key)
}

// issueSessionToken is the console session token login and init return.
func (s *Server) issueSessionToken() (string, error) {
	return signToken(s.jwtKey, jwtTTL)
}

// parseToken verifies raw with key through tokenParser and returns its claims.
// Only the canonical spelling of a token verifies, so the raw string is a
// stable identity for it (the change-password limiter key).
func parseToken(raw string, key []byte) (*jwt.RegisteredClaims, error) {
	if raw == "" {
		return nil, errNoToken
	}
	if len(raw) > maxTokenBytes || !canonicalToken(raw) {
		return nil, errInvalidToken
	}
	var claims jwt.RegisteredClaims
	if _, err := tokenParser.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) {
		return key, nil
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidToken, err)
	}
	return &claims, nil
}

// authenticate is the single verifier of console tokens: requireAuth, health,
// change-password and approver all go through it. It returns errNoToken or
// errInvalidToken (wrapped) when the request carries no valid token.
func (s *Server) authenticate(r *http.Request) (authInfo, error) {
	raw := extractToken(r)
	claims, err := parseToken(raw, s.jwtKey)
	if err != nil {
		return authInfo{}, err
	}
	return authInfo{raw: raw, subject: claims.Subject}, nil
}

// requestAuth is the authInfo requireAuth stored for r. Handlers called
// without requireAuth (tests call some directly) verify the token here.
func (s *Server) requestAuth(r *http.Request) (authInfo, error) {
	if info, ok := r.Context().Value(authInfoKey{}).(authInfo); ok {
		return info, nil
	}
	return s.authenticate(r)
}

// approver is who a human decision is recorded for: the subject of the
// request's session token, or "" without a valid one.
func (s *Server) approver(r *http.Request) string {
	info, err := s.requestAuth(r)
	if err != nil {
		return ""
	}
	return info.subject
}

// extractToken reads the JWT from Authorization: Bearer header,
// artex_token cookie, or ?token= query param (for SSE connections).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// authExempt is the exact set of /api paths served without a token: what the
// login and setup pages call before a token exists, and the health probe. The
// match is on the exact path, never a prefix: the root mux has already
// redirected dot segments, and a decoded %2e%2e path matches no entry.
var authExempt = map[string]bool{
	"/api/auth/status": true,
	"/api/auth/init":   true,
	"/api/auth/login":  true,
	"/api/health":      true,
}

// requireAuth wraps h with token verification, except for the authExempt
// paths. The verified authInfo goes into the request context.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authExempt[r.URL.Path] {
			h.ServeHTTP(w, r)
			return
		}
		info, err := s.authenticate(r)
		if err != nil {
			msg := "token is invalid or expired"
			if errors.Is(err, errNoToken) {
				msg = "Unauthorized"
			}
			writeErr(w, 401, msg)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authInfoKey{}, info)))
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// A read failure must answer 503, not initialized:false: on initialized:false the
// frontend ships the user to /setup to set a password (login/page.tsx); wrapping a
// database outage in a 200 pushes the user toward overwriting the existing password.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// initSetupToken generates the one-time setup token when no admin password is set
// and writes it to the server log. Without it, anyone who can reach the port
// before the operator could claim the instance through POST /api/auth/init.
func (s *Server) initSetupToken() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	if hash, _, err := s.m.pg.GetSetting(authPassKey); err == nil && hash != "" {
		return
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("[auth] generate setup token: %v", err)
	}
	s.setupToken = hex.EncodeToString(buf)
	log.Printf("[auth] no admin password is set. Setup token for the /setup page: %s", s.setupToken)
}

// checkSetupToken compares got with the active setup token in constant time.
// It fails when no token is active.
func (s *Server) checkSetupToken(got string) bool {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.setupToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.setupToken)) == 1
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
// Requires the setup token from the server log.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "Password is already set")
		return
	}
	var req struct {
		Password   string `json:"password"`
		SetupToken string `json:"setup_token"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, "Password cannot be empty")
		return
	}
	// 403, not 401: the frontend treats any 401 as an expired session and redirects to /login.
	if !s.checkSetupToken(req.SetupToken) {
		writeErr(w, 403, "Invalid setup token. The server log prints it at startup while no password is set")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	// INSERT ... ON CONFLICT DO NOTHING instead of an upsert: the GetSetting above is
	// only a fast-fail path; the real "first-set-only" guarantee rests on the primary
	// key. bcrypt runs tens of milliseconds, another request may set the password meanwhile, and the read check itself can fail under an outage.
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 500, "Save failed: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "Password is already set")
		return
	}
	s.setupMu.Lock()
	s.setupToken = ""
	s.setupMu.Unlock()
	tok, err := s.issueSessionToken()
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. requireAuth has
// verified the session token; the current password is required as well.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	s.changePassword(w, r, pg.GetSetting, pg.SetSetting)
}

// changePassword is authChangePassword past the data-source check; getSetting
// and setSetting are pg.GetSetting and pg.SetSetting, parameters so tests can
// run it without PostgreSQL.
//
// Every attempt counts against the presented token (s.pwLimit, a limiter of
// its own with the login parameters), so failed logins and requests with
// another token do not count against it; a successful change clears it. While
// the artex_token cookie is still accepted, a same-site page can spend it too.
// A wrong current password answers 403, not 401: the browser treats any 401
// as an expired session and signs out.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request,
	getSetting func(string) (string, bool, error), setSetting func(string, string) error) {
	info, err := s.requestAuth(r)
	if err != nil {
		writeErr(w, 401, "Unauthorized")
		return
	}
	key := passwordLimitKey(info.raw)
	if wait := s.pwLimit.allow(key); wait > 0 {
		secs := retryAfterSeconds(wait)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeErr(w, 429, fmt.Sprintf("Too many password change attempts, try again in %d seconds", secs))
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "New password cannot be empty")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := getSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "Password not initialized; set a password first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 403, "Current password is wrong")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "Password encryption failed")
		return
	}
	if err := setSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, "Save failed: "+err.Error())
		return
	}
	s.pwLimit.reset(key)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// passwordLimitKey is the s.pwLimit key of a token: a hash, so the limiter
// never holds a usable token.
func passwordLimitKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "tok:" + hex.EncodeToString(sum[:])
}

// retryAfterSeconds rounds a limiter wait up to whole seconds for Retry-After.
func retryAfterSeconds(wait time.Duration) int {
	return int((wait + time.Second - 1) / time.Second)
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	s.login(w, r, pg.GetSetting)
}

// login is authLogin past the data-source check; getSetting is pg.GetSetting,
// a parameter so tests can run it without PostgreSQL. Every attempt counts
// against the caller's IP (s.loginLimit, keyed by clientIP) and a successful
// one clears it. There is no per-account lockout and no password length check here.
func (s *Server) login(w http.ResponseWriter, r *http.Request, getSetting func(string) (string, bool, error)) {
	ip := clientIP(r, s.trustedProxies)
	if wait := s.loginLimit.allow(ip); wait > 0 {
		secs := retryAfterSeconds(wait)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeErr(w, 429, fmt.Sprintf("Too many login attempts, try again in %d seconds", secs))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "Invalid request format")
		return
	}
	if req.Username != "ARTEX" {
		writeErr(w, 401, "Incorrect username or password")
		return
	}
	hash, ok, err := getSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "Password not initialized; set a password first")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, 401, "Incorrect username or password")
		return
	}
	s.loginLimit.reset(ip)
	tok, err := s.issueSessionToken()
	if err != nil {
		writeErr(w, 500, "token generation failed")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
