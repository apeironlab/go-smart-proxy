package main

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTokenLifecycleAndRefusals(t *testing.T) {
	localAuthEnv(t)
	// the token endpoints are not available while the token is off
	for _, c := range []struct{ method, path string }{{"POST", "/api/auth/rotate"}, {"GET", "/api/auth/token"}} {
		if w, _ := apiCall(t, c.method, c.path, nil, nil); w.Code != http.StatusConflict {
			t.Errorf("%s %s while off: %d", c.method, c.path, w.Code)
		}
	}
	// bodies that are not JSON
	if w, _ := apiCall(t, "PUT", "/api/auth/config", "not an object", nil); w.Code != http.StatusBadRequest {
		t.Errorf("config with a bad body: %d", w.Code)
	}
	if w, _ := apiCall(t, "POST", "/api/auth/login", "not an object", nil); w.Code != http.StatusBadRequest {
		t.Errorf("login with a bad body: %d", w.Code)
	}
	// switching it on creates the token file; a later start reads the same token
	if w, _ := apiCall(t, "PUT", "/api/auth/config", map[string]any{"enabled": true}, nil); w.Code != http.StatusOK {
		t.Fatalf("enable: %d", w.Code)
	}
	first, err := currentToken()
	if err != nil || len(first) < 32 {
		t.Fatalf("token %q %v", first, err)
	}
	if info := tokenFilePath(); !strings.HasSuffix(info, apiTokenFile) {
		t.Errorf("token file path %q", info)
	}
	localAuth.mu.Lock()
	localAuth.token = "" // as after a restart
	localAuth.mu.Unlock()
	if again, _ := currentToken(); again != first {
		t.Error("the token changed across a restart")
	}
	// a damaged token file is replaced
	localAuth.mu.Lock()
	localAuth.token = ""
	localAuth.mu.Unlock()
	os.WriteFile(apiTokenFile, []byte("short"), 0o600)
	if fresh, err := currentToken(); err != nil || fresh == first || len(fresh) < 32 {
		t.Errorf("a short token file was reused: %q %v", fresh, err)
	}
	// sessions expire: an old one is dropped when a new one is made
	now := time.Now()
	localAuth.mu.Lock()
	localAuth.sessions = map[string]*localSession{
		"old": {created: now.Add(-48 * time.Hour), last: now.Add(-48 * time.Hour)},
	}
	localAuth.mu.Unlock()
	cookie := newSession()
	localAuth.mu.Lock()
	_, oldLeft := localAuth.sessions["old"]
	localAuth.mu.Unlock()
	if oldLeft {
		t.Error("an expired session was kept")
	}
	if !sessionValid(cookie) || sessionValid("") || sessionValid("nonsense") {
		t.Error("session validity")
	}
	localAuth.mu.Lock()
	localAuth.sessions[hashOf(cookie)].last = now.Add(-48 * time.Hour)
	localAuth.mu.Unlock()
	if sessionValid(cookie) {
		t.Error("an idle session stayed valid")
	}
	if tokenMatches("") {
		t.Error("an empty token matched")
	}
	tok, _ := currentToken()
	if w, _ := apiCall(t, "GET", "/api/auth/token", nil, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }); w.Code != http.StatusOK {
		t.Errorf("the token is shown to a signed-in page: %d", w.Code)
	}
}
