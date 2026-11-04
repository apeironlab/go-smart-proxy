package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/apeironlab/go-smart-proxy/relay"
)

// localAuthEnv is a configuration that can be saved, in a directory of its own,
// with a clean token and session state.
func localAuthEnv(t *testing.T) {
	t.Helper()
	secretsEnv(t, "the master password")
	localAuth.mu.Lock()
	localAuth.token, localAuth.sessions, localAuth.failures = "", nil, nil
	localAuth.mu.Unlock()
	relayHub.reset()
	t.Cleanup(relayHub.reset)
}

// apiCall goes through the proxy handler, as a browser does.
func apiCall(t *testing.T, method, path string, body any, mod func(r *http.Request)) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Host = "127.0.0.1:3128"
	req.RemoteAddr = "127.0.0.1:50000"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if mod != nil {
		mod(req)
	}
	w := httptest.NewRecorder()
	proxyHandler(w, req)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func sessionCookieOf(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	return nil
}

func TestAPIIsOpenUntilTheTokenIsSwitchedOn(t *testing.T) {
	localAuthEnv(t)
	if w, _ := apiCall(t, "GET", "/api/state", nil, nil); w.Code != 200 {
		t.Fatalf("no token configured: %d", w.Code)
	}
	if w, out := apiCall(t, "GET", "/api/auth/info", nil, nil); w.Code != 200 || out["required"] != false || out["signedIn"] != true {
		t.Fatalf("info: %d %v", w.Code, out)
	}
	if _, err := os.Stat(apiTokenFile); err == nil {
		t.Fatal("a token file exists although the token is not in use")
	}
}

func TestTokenProtectsTheAPIButNotThePage(t *testing.T) {
	localAuthEnv(t)
	// switch it on through the API, as the Security tab does
	w, out := apiCall(t, "PUT", "/api/auth/config", map[string]bool{"enabled": true}, nil)
	if w.Code != 200 || out["enabled"] != true {
		t.Fatalf("enable: %d %v", w.Code, out)
	}
	if c := sessionCookieOf(w); c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("the page that switched it on must stay signed in: %+v", c)
	}
	st, err := os.Stat(apiTokenFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", st, err)
	}
	raw, _ := os.ReadFile(apiTokenFile)
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 {
		t.Fatalf("a short token: %q", token)
	}

	// nothing gets through without it
	for _, p := range []string{"/api/state", "/api/blocking", "/api/security", "/api/relays", "/api/config"} {
		if w, out := apiCall(t, "GET", p, nil, nil); w.Code != 401 || out["authRequired"] != true || w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%s without a token: %d %v", p, w.Code, out)
		}
	}
	if w, _ := apiCall(t, "POST", "/api/force-route", map[string]string{"name": "x"}, nil); w.Code != 401 {
		t.Fatalf("a write without a token: %d", w.Code)
	}
	// the page that asks for the token is served
	if w, _ := apiCall(t, "GET", "/", nil, nil); w.Code != 200 {
		t.Fatalf("the page: %d", w.Code)
	}
	if w, out := apiCall(t, "GET", "/api/auth/info", nil, nil); w.Code != 200 || out["required"] != true || out["signedIn"] != false || out["tokenFile"] == nil {
		t.Fatalf("info: %d %v", w.Code, out)
	}
	// a bearer token works, a wrong one does not
	bearer := func(tok string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
	}
	if w, _ := apiCall(t, "GET", "/api/state", nil, bearer(token)); w.Code != 200 {
		t.Fatalf("bearer: %d", w.Code)
	}
	if w, _ := apiCall(t, "GET", "/api/state", nil, bearer(token+"x")); w.Code != 401 {
		t.Fatalf("wrong bearer: %d", w.Code)
	}
	// the proxy itself (a request for another host) is not affected
	if w, _ := apiCall(t, "GET", "/api/state", nil, func(r *http.Request) { r.Header.Set("Cookie", sessionCookie+"=forged") }); w.Code != 401 {
		t.Fatalf("forged cookie: %d", w.Code)
	}
}

func TestSigningInWithTheToken(t *testing.T) {
	localAuthEnv(t)
	apiCall(t, "PUT", "/api/auth/config", map[string]bool{"enabled": true}, nil)
	token, _ := currentToken()

	if w, _ := apiCall(t, "POST", "/api/auth/login", map[string]string{"token": "nope"}, nil); w.Code != 401 || sessionCookieOf(w) != nil {
		t.Fatalf("wrong token: %d", w.Code)
	}
	w, _ := apiCall(t, "POST", "/api/auth/login", map[string]string{"token": token + "\n"}, nil)
	c := sessionCookieOf(w)
	if w.Code != 200 || c == nil {
		t.Fatalf("login: %d", w.Code)
	}
	withCookie := func(r *http.Request) { r.AddCookie(c) }
	if w, _ := apiCall(t, "GET", "/api/state", nil, withCookie); w.Code != 200 {
		t.Fatalf("session: %d", w.Code)
	}
	if w, out := apiCall(t, "GET", "/api/auth/info", nil, withCookie); out["signedIn"] != true || w.Code != 200 {
		t.Fatalf("info signed in: %v", out)
	}
	// the token itself can be read once signed in, not before
	if w, _ := apiCall(t, "GET", "/api/auth/token", nil, nil); w.Code != 401 {
		t.Fatalf("token read without signing in: %d", w.Code)
	}
	if w, out := apiCall(t, "GET", "/api/auth/token", nil, withCookie); w.Code != 200 || out["token"] != token {
		t.Fatalf("token read: %d", w.Code)
	}
	// signing out ends the session
	apiCall(t, "POST", "/api/auth/logout", nil, withCookie)
	if w, _ := apiCall(t, "GET", "/api/state", nil, withCookie); w.Code != 401 {
		t.Fatalf("after logout: %d", w.Code)
	}
}

func TestGuessingTheTokenIsLimited(t *testing.T) {
	localAuthEnv(t)
	apiCall(t, "PUT", "/api/auth/config", map[string]bool{"enabled": true}, nil)
	token, _ := currentToken()
	for i := 0; i < 10; i++ {
		if w, _ := apiCall(t, "POST", "/api/auth/login", map[string]string{"token": "guess"}, nil); w.Code != 401 {
			t.Fatalf("guess %d: %d", i, w.Code)
		}
	}
	// the right token is not tried while the limit holds
	if w, _ := apiCall(t, "POST", "/api/auth/login", map[string]string{"token": token}, nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("after many guesses: %d", w.Code)
	}
}

func TestRotatingTheToken(t *testing.T) {
	localAuthEnv(t)
	apiCall(t, "PUT", "/api/auth/config", map[string]bool{"enabled": true}, nil)
	old, _ := currentToken()
	// two browsers
	w1, _ := apiCall(t, "POST", "/api/auth/login", map[string]string{"token": old}, nil)
	w2, _ := apiCall(t, "POST", "/api/auth/login", map[string]string{"token": old}, nil)
	c1, c2 := sessionCookieOf(w1), sessionCookieOf(w2)
	w, _ := apiCall(t, "POST", "/api/auth/rotate", nil, func(r *http.Request) { r.AddCookie(c1) })
	c1b := sessionCookieOf(w)
	if w.Code != 200 || c1b == nil {
		t.Fatalf("rotate: %d", w.Code)
	}
	fresh, _ := currentToken()
	if fresh == old {
		t.Fatal("the token did not change")
	}
	if raw, _ := os.ReadFile(apiTokenFile); strings.TrimSpace(string(raw)) != fresh {
		t.Fatal("the file was not updated")
	}
	if w, _ := apiCall(t, "GET", "/api/state", nil, func(r *http.Request) { r.AddCookie(c2) }); w.Code != 401 {
		t.Fatalf("another session survived: %d", w.Code)
	}
	if w, _ := apiCall(t, "GET", "/api/state", nil, func(r *http.Request) { r.AddCookie(c1) }); w.Code != 401 {
		t.Fatalf("the old cookie of the caller survived: %d", w.Code)
	}
	if w, _ := apiCall(t, "GET", "/api/state", nil, func(r *http.Request) { r.AddCookie(c1b) }); w.Code != 200 {
		t.Fatalf("the caller was signed out: %d", w.Code)
	}
	if w, _ := apiCall(t, "GET", "/api/state", nil, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+old) }); w.Code != 401 {
		t.Fatalf("the old token still works: %d", w.Code)
	}
}

func TestARelayCanRequireTheTokenAndTheUserCannotSwitchItOff(t *testing.T) {
	localAuthEnv(t)
	if w, _ := apiCall(t, "GET", "/api/state", nil, nil); w.Code != 200 {
		t.Fatal("open before the relay says anything")
	}
	setRelayPolicy(t, "corp", &relay.PolicyPush{Rev: "1", RequireLocalAuth: true})
	if w, out := apiCall(t, "GET", "/api/state", nil, nil); w.Code != 401 || out["authRequired"] != true {
		t.Fatalf("imposed: %d %v", w.Code, out)
	}
	token, err := currentToken() // made on demand
	if err != nil {
		t.Fatal(err)
	}
	if w, out := apiCall(t, "GET", "/api/auth/info", nil, nil); out["imposed"] != true || out["required"] != true || w.Code != 200 {
		t.Fatalf("info: %v", out)
	}
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
	if w, out := apiCall(t, "PUT", "/api/auth/config", map[string]bool{"enabled": false}, bearer); w.Code != 403 {
		t.Fatalf("switching it off: %d %v", w.Code, out)
	}
	// the relay lifts it: back to the user's own choice
	setRelayPolicy(t, "corp", &relay.PolicyPush{Rev: "2"})
	if w, _ := apiCall(t, "GET", "/api/state", nil, nil); w.Code != 200 {
		t.Fatalf("after the relay lifted it: %d", w.Code)
	}
}

func TestOpeningTheInterfaceCarriesTheTokenAfterAHash(t *testing.T) {
	localAuthEnv(t)
	configuration.Address = "127.0.0.1:3128"
	if u := webUIOpenURL(); u != "http://127.0.0.1:3128/" {
		t.Fatalf("no token in use: %s", u)
	}
	apiCall(t, "PUT", "/api/auth/config", map[string]bool{"enabled": true}, nil)
	token, _ := currentToken()
	if u := webUIOpenURL(); u != "http://127.0.0.1:3128/#token="+token {
		t.Fatalf("with the token: %s", u)
	}
}
