package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The web interface and its API are reachable by anything that can open a
// connection to 127.0.0.1, which on a computer with several users or with
// untrusted programs is more than the owner. They can be protected by an access
// token, kept in api.token (readable by this user only). It is switched on in
// Configuration → Security, or imposed by a relay (its policy can require it),
// in which case the user cannot switch it off.
//
// The page that loads the interface needs no token (it has to show the sign-in
// form); every /api/ call does, as a bearer token or as the cookie the sign-in
// sets. The tray and the "open" actions put the token in the address after a
// "#", which the browser never sends anywhere: the page reads it, signs in and
// removes it from the address bar.

const (
	apiTokenFile  = "api.token"
	sessionCookie = "gsp_session"
	sessionIdle   = 2 * time.Hour
	sessionMax    = 12 * time.Hour
)

// LocalAuthConfig is the user's own choice.
type LocalAuthConfig struct {
	Enabled bool `yaml:"Enabled" json:"enabled"`
}

type localSession struct {
	created, last time.Time
}

var localAuth struct {
	mu       sync.Mutex
	token    string
	sessions map[string]*localSession // by hash of the cookie value
	failures []time.Time
}

// relaysRequireLocalAuth says whether a relay's policy imposes the token.
func relaysRequireLocalAuth() bool {
	for _, p := range relayPolicies() {
		if p.RequireLocalAuth {
			return true
		}
	}
	return false
}

func localAuthImposed() bool { return relaysRequireLocalAuth() }

func localAuthEnabled() bool {
	configMu.Lock()
	on := configuration.LocalAuth.Enabled
	configMu.Unlock()
	return on || localAuthImposed()
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("no secure random source: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// currentToken returns the access token, creating api.token on first use.
func currentToken() (string, error) {
	localAuth.mu.Lock()
	defer localAuth.mu.Unlock()
	if localAuth.token != "" {
		return localAuth.token, nil
	}
	if b, err := os.ReadFile(apiTokenFile); err == nil {
		if t := strings.TrimSpace(string(b)); len(t) >= 32 {
			localAuth.token = t
			return t, nil
		}
	}
	return writeTokenLocked(newToken())
}

func writeTokenLocked(t string) (string, error) {
	if err := writeSecretFileAtomic(apiTokenFile, []byte(t+"\n")); err != nil {
		return "", err
	}
	localAuth.token = t
	return t, nil
}

// rotateToken makes a new token and ends every session.
func rotateToken() (string, error) {
	localAuth.mu.Lock()
	defer localAuth.mu.Unlock()
	localAuth.sessions = nil
	return writeTokenLocked(newToken())
}

func tokenFilePath() string {
	p, err := filepath.Abs(apiTokenFile)
	if err != nil {
		return apiTokenFile
	}
	return p
}

func tokenMatches(got string) bool {
	want, err := currentToken()
	if err != nil || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func newSession() string {
	v := newToken()
	now := time.Now()
	localAuth.mu.Lock()
	defer localAuth.mu.Unlock()
	if localAuth.sessions == nil {
		localAuth.sessions = map[string]*localSession{}
	}
	for k, s := range localAuth.sessions {
		if now.Sub(s.created) > sessionMax || now.Sub(s.last) > sessionIdle {
			delete(localAuth.sessions, k)
		}
	}
	localAuth.sessions[hashOf(v)] = &localSession{created: now, last: now}
	return v
}

func sessionValid(v string) bool {
	if v == "" {
		return false
	}
	now := time.Now()
	localAuth.mu.Lock()
	defer localAuth.mu.Unlock()
	s := localAuth.sessions[hashOf(v)]
	if s == nil || now.Sub(s.created) > sessionMax || now.Sub(s.last) > sessionIdle {
		delete(localAuth.sessions, hashOf(v))
		return false
	}
	s.last = now
	return true
}

func setSessionCookie(w http.ResponseWriter, v string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: v, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionMax / time.Second),
	})
}

// loginAllowed limits guessing: ten wrong tokens a minute.
func loginAllowed() bool {
	localAuth.mu.Lock()
	defer localAuth.mu.Unlock()
	cut := time.Now().Add(-time.Minute)
	kept := localAuth.failures[:0]
	for _, t := range localAuth.failures {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	localAuth.failures = kept
	return len(kept) < 10
}

func loginFailed() {
	localAuth.mu.Lock()
	localAuth.failures = append(localAuth.failures, time.Now())
	localAuth.mu.Unlock()
}

// authorized reports whether a request carries the token or a valid session.
func authorized(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return tokenMatches(strings.TrimPrefix(h, "Bearer "))
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		return sessionValid(c.Value)
	}
	return false
}

// localAuthGate decides whether an API request may go on. It answers 401 itself
// when it may not.
func localAuthGate(w http.ResponseWriter, r *http.Request) bool {
	if !localAuthEnabled() {
		return true
	}
	switch r.URL.Path {
	case "/api/auth/info", "/api/auth/login":
		return true
	}
	if authorized(r) {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="go-smart-proxy"`)
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]any{"error": "access token required", "authRequired": true})
	return false
}

func registerLocalAuthRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/auth/info", func(w http.ResponseWriter, r *http.Request) {
		on := localAuthEnabled()
		out := map[string]any{"required": on, "imposed": localAuthImposed(), "signedIn": !on || authorized(r)}
		if on {
			out["tokenFile"] = tokenFilePath()
		}
		writeJSON(w, out)
	})
	m.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		if err := readJSON(r, &body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if !loginAllowed() {
			writeAPIError(w, http.StatusTooManyRequests, "too many attempts: wait a minute")
			return
		}
		if !tokenMatches(strings.TrimSpace(body.Token)) {
			loginFailed()
			writeAPIError(w, http.StatusUnauthorized, "wrong access token")
			return
		}
		setSessionCookie(w, newSession())
		writeJSON(w, map[string]string{"status": "ok"})
	})
	m.HandleFunc("POST /api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			localAuth.mu.Lock()
			delete(localAuth.sessions, hashOf(c.Value))
			localAuth.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
		writeJSON(w, map[string]string{"status": "ok"})
	})
	// Switch the token on or off. Turning it on signs the caller in, so that
	// the page that asked does not lock itself out.
	m.HandleFunc("PUT /api/auth/config", func(w http.ResponseWriter, r *http.Request) {
		var body LocalAuthConfig
		if err := readJSON(r, &body); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if !body.Enabled && localAuthImposed() {
			writeAPIError(w, http.StatusForbidden, "your organization requires the access token")
			return
		}
		if body.Enabled {
			if _, err := currentToken(); err != nil {
				writeAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		configMu.Lock()
		old := configuration.LocalAuth
		configuration.LocalAuth = body
		err := persistConfigurationLocked()
		if err != nil {
			configuration.LocalAuth = old
		}
		configMu.Unlock()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if body.Enabled {
			setSessionCookie(w, newSession())
		}
		writeJSON(w, map[string]any{"status": "ok", "enabled": body.Enabled})
	})
	m.HandleFunc("POST /api/auth/rotate", func(w http.ResponseWriter, r *http.Request) {
		if !localAuthEnabled() {
			writeAPIError(w, http.StatusConflict, "the access token is not in use")
			return
		}
		if _, err := rotateToken(); err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		setSessionCookie(w, newSession()) // this page stays signed in; the others are out
		writeJSON(w, map[string]string{"status": "ok"})
	})
	m.HandleFunc("GET /api/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if !localAuthEnabled() {
			writeAPIError(w, http.StatusConflict, "the access token is not in use")
			return
		}
		t, err := currentToken()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]string{"token": t})
	})
}

// webUIOpenURL is the address to open the interface at: it carries the token
// when one is needed, after "#" so that it goes nowhere but into the page.
func webUIOpenURL() string {
	u := webUIURL()
	if localAuthEnabled() {
		if t, err := currentToken(); err == nil {
			return u + "#token=" + t
		}
	}
	return u
}
