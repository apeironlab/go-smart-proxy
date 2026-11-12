package relay

import (
	"net/http"
	"testing"
)

func TestAdminAPIRefusesBadRequests(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	b := f.loggedIn(t)

	// every writing endpoint refuses a body that is not what it expects
	for _, path := range []string{
		"/admin/api/invite", "/admin/api/revoke", "/admin/api/unrevoke", "/admin/api/kick",
		"/admin/api/revoke-device", "/admin/api/local-users", "/admin/api/gateways",
	} {
		if code, _ := b.do("POST", path, "this is a string, not an object", nil); code != http.StatusBadRequest {
			t.Errorf("POST %s with a bad body: %d", path, code)
		}
	}
	for _, path := range []string{"/admin/api/apps", "/admin/api/policy", "/admin/api/rules"} {
		if code, _ := b.do("PUT", path, "not an object", nil); code < 400 { // refused, or not enabled on this relay
			t.Errorf("PUT %s with a bad body: %d", path, code)
		}
	}
	// well-formed but wrong
	for name, c := range map[string]struct {
		method, path string
		body         any
	}{
		"invite a non-address":       {"POST", "/admin/api/invite", map[string]string{"email": "nonsense"}},
		"revoke a non-address":       {"POST", "/admin/api/revoke", map[string]string{"email": "nonsense"}},
		"unrevoke a non-address":     {"POST", "/admin/api/unrevoke", map[string]string{"email": "nonsense"}},
		"kick nobody":                {"POST", "/admin/api/kick", map[string]string{"email": "nonsense"}},
		"user without a name":        {"POST", "/admin/api/local-users", map[string]any{"username": "", "password": "a long enough password"}},
		"user with a short password": {"POST", "/admin/api/local-users", map[string]any{"username": "bob", "password": "x", "email": "bob@example.com"}},
		"gateway with a bad id":      {"POST", "/admin/api/gateways", map[string]string{"id": "Bad Id!"}},
		"edit an unknown user":       {"PUT", "/admin/api/local-users/nobody", map[string]any{"email": "n@example.com"}},
		"delete an unknown user":     {"DELETE", "/admin/api/local-users/nobody", nil},
	} {
		if code, body := b.do(c.method, c.path, c.body, nil); code < 400 {
			t.Errorf("%s: accepted with %d %s", name, code, body)
		}
	}
	// the lists a page shows
	for _, path := range []string{
		"/admin/api/overview", "/admin/api/users", "/admin/api/certs?email=bob@example.com", "/admin/api/devices?email=bob@example.com", "/admin/api/local-users",
		"/admin/api/apps", "/admin/api/policy", "/admin/api/gateways", "/admin/api/rules", "/admin/api/events",
	} {
		if code, body := b.do("GET", path, nil, nil); code != http.StatusOK {
			t.Errorf("GET %s: %d %s", path, code, body)
		}
	}
	// without the token that proves the page's origin nothing is written
	anon := f.browser(t)
	if code, _ := anon.do("POST", "/admin/api/revoke", map[string]string{"email": "a@example.com"}, nil); code < 400 {
		t.Errorf("an anonymous revoke: %d", code)
	}
	if code, _ := anon.do("GET", "/admin/api/overview", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("an anonymous overview: %d", code)
	}
	b.send("POST", "/admin/api/logout", nil, nil, http.StatusOK)
	if code, _ := b.do("GET", "/admin/api/overview", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("after the logout: %d", code)
	}
}

func TestAdminLocalUserLifecycleAndRevocations(t *testing.T) {
	f := newAdminFixture(t, adminOpts{})
	b := f.loggedIn(t)
	b.send("POST", "/admin/api/local-users", map[string]any{"username": "bob", "password": "a long enough password", "email": "bob@example.com", "groups": []string{"staff"}}, nil, http.StatusOK)
	if code, _ := b.do("POST", "/admin/api/local-users", map[string]any{"username": "bob", "password": "a long enough password", "email": "bob@example.com"}, nil); code != http.StatusConflict {
		t.Errorf("a duplicate user: %d", code)
	}
	b.send("PUT", "/admin/api/local-users/bob", map[string]any{"password": "another long password", "email": "bob@example.com", "groups": []string{"staff", "ops"}}, nil, http.StatusOK)
	var users struct {
		Users []map[string]any `json:"users"`
	}
	b.get("/admin/api/local-users", &users, http.StatusOK)
	if len(users.Users) < 2 {
		t.Errorf("users = %v", users)
	}
	// revoke by address and by serial, then lift both
	b.send("POST", "/admin/api/revoke", map[string]string{"email": "bob@example.com"}, nil, http.StatusOK)
	if code, _ := b.do("POST", "/admin/api/revoke", map[string]string{"serial": "abcdef"}, nil); code != http.StatusBadRequest {
		t.Errorf("a serial that was never issued: %d", code)
	}
	if code, _ := b.do("POST", "/admin/api/revoke", map[string]string{"email": "root@example.com"}, nil); code != http.StatusBadRequest {
		t.Errorf("revoking yourself: %d", code)
	}
	if code, _ := b.do("POST", "/admin/api/revoke", map[string]string{}, nil); code != http.StatusBadRequest {
		t.Errorf("revoking nothing: %d", code)
	}
	var certs any
	b.get("/admin/api/certs?email=bob@example.com", &certs, http.StatusOK)
	b.send("POST", "/admin/api/unrevoke", map[string]string{"email": "bob@example.com"}, nil, http.StatusOK)
	b.send("DELETE", "/admin/api/local-users/bob", nil, nil, http.StatusOK)
	var ev []map[string]any
	b.get("/admin/api/events", &ev, http.StatusOK)
	if len(ev) == 0 {
		t.Error("the audit log is empty after these actions")
	}
}
