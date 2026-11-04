package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func apiReq(method, host, path, body string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	r.RequestURI = path
	r.URL.Scheme, r.URL.Host = "", ""
	r.Host = host
	r.RemoteAddr = "127.0.0.1:50000"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestLocalUIRequestChecks(t *testing.T) {
	json := map[string]string{"Content-Type": "application/json"}
	cases := []struct {
		name string
		r    *http.Request
		ok   bool
	}{
		{"same-origin json post", apiReq("POST", "127.0.0.1:3128", "/api/config", `{}`, map[string]string{"Content-Type": "application/json", "Origin": "http://127.0.0.1:3128", "Sec-Fetch-Site": "same-origin"}), true},
		{"plain GET, no browser headers", apiReq("GET", "127.0.0.1:3128", "/api/state", "", nil), true},
		{"localhost host", apiReq("GET", "localhost:3128", "/api/state", "", nil), true},
		{"ipv6 loopback host", apiReq("GET", "[::1]:3128", "/api/state", "", nil), true},
		{"dns rebinding host", apiReq("GET", "evil.example:3128", "/api/state", "", nil), false},
		{"rebinding host on the UI too", apiReq("GET", "evil.example:3128", "/", "", nil), false},
		{"cross-origin simple POST (text/plain)", apiReq("POST", "127.0.0.1:3128", "/api/routes", `{"name":"x"}`, map[string]string{"Content-Type": "text/plain", "Origin": "https://evil.example"}), false},
		{"cross-origin json POST", apiReq("POST", "127.0.0.1:3128", "/api/routes", `{}`, map[string]string{"Content-Type": "application/json", "Origin": "https://evil.example"}), false},
		{"origin null", apiReq("POST", "127.0.0.1:3128", "/api/routes", `{}`, map[string]string{"Content-Type": "application/json", "Origin": "null"}), false},
		{"cross-site fetch metadata", apiReq("GET", "127.0.0.1:3128", "/api/state", "", map[string]string{"Sec-Fetch-Site": "cross-site"}), false},
		{"same-site fetch metadata", apiReq("GET", "127.0.0.1:3128", "/api/state", "", map[string]string{"Sec-Fetch-Site": "same-site"}), false},
		{"no content type with body", apiReq("POST", "127.0.0.1:3128", "/api/config", `{}`, nil), false},
		{"json with charset", apiReq("POST", "127.0.0.1:3128", "/api/config", `{}`, map[string]string{"Content-Type": "application/json; charset=utf-8"}), true},
		{"empty POST needs no content type", apiReq("POST", "127.0.0.1:3128", "/api/connections/1/close", "", nil), true},
		{"static UI is not subject to API-only checks", apiReq("GET", "127.0.0.1:3128", "/assets/app.js", "", map[string]string{"Sec-Fetch-Site": "cross-site"}), true},
	}
	_ = json
	for _, c := range cases {
		got := checkLocalUIRequest(c.r) == ""
		if got != c.ok {
			t.Errorf("%s: allowed=%v, want %v (%s)", c.name, got, c.ok, checkLocalUIRequest(c.r))
		}
	}
}

func TestProxyHandlerRejectsCSRFAndRebinding(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	do := func(r *http.Request) int {
		w := httptest.NewRecorder()
		proxyHandler(w, r)
		return w.Code
	}
	if code := do(apiReq("GET", "127.0.0.1:3128", "/api/state", "", nil)); code != 200 {
		t.Fatalf("legitimate API call: %d", code)
	}
	if code := do(apiReq("GET", "attacker.example:3128", "/api/state", "", nil)); code != 403 {
		t.Fatalf("DNS rebinding must be refused, got %d", code)
	}
	csrf := apiReq("POST", "127.0.0.1:3128", "/api/force-route", `{"name":"x"}`, map[string]string{"Content-Type": "text/plain", "Origin": "https://attacker.example"})
	if code := do(csrf); code != 403 {
		t.Fatalf("CSRF must be refused, got %d", code)
	}
}

func TestSelfTargetsAreRefused(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	configuration.Address = "127.0.0.1:3128"
	configuration.SocksAddress = "127.0.0.1:1080"
	for _, c := range []struct {
		host, port string
		want       bool
	}{
		{"127.0.0.1", "3128", true},
		{"localhost", "3128", true},
		{"::1", "3128", true},
		{"0.0.0.0", "3128", true},
		{"127.0.0.1", "1080", true},
		{"127.1.2.3", "3128", true},
		{"127.0.0.1", "8080", false},
		{"93.184.216.34", "3128", false},
		{"example.com", "443", false},
	} {
		if got := isSelfTarget(c.host, c.port); got != c.want {
			t.Errorf("isSelfTarget(%s, %s) = %v, want %v", c.host, c.port, got, c.want)
		}
	}

	if _, _, _, err := dialTarget("tunnel", "127.0.0.1:1", "127.0.0.1", "3128", "CONNECT", ""); err == nil {
		t.Fatal("CONNECT to the proxy itself must be refused")
	}

	// An absolute-form request to the proxy's own API must not be forwarded.
	r := httptest.NewRequest("GET", "http://127.0.0.1:3128/api/config", nil)
	r.RemoteAddr = "127.0.0.1:50000"
	w := httptest.NewRecorder()
	proxyHandler(w, r)
	if w.Code != 403 {
		t.Fatalf("self request through the proxy: %d, want 403", w.Code)
	}
}

type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (f fakeConn) RemoteAddr() net.Addr { return f.remote }

func tcpAddr(s string) net.Addr { a, _ := net.ResolveTCPAddr("tcp", s); return a }

func TestAcceptClientPolicy(t *testing.T) {
	resetEnv(t, nil, nil)
	remote := fakeConn{remote: tcpAddr("192.168.1.50:5555")}
	local := fakeConn{remote: tcpAddr("127.0.0.1:5555")}
	local6 := fakeConn{remote: tcpAddr("[::1]:5555")}
	if !acceptClient(local) || !acceptClient(local6) {
		t.Fatal("loopback clients must be served")
	}
	if acceptClient(remote) {
		t.Fatal("remote clients must be refused by default")
	}
	configuration.AllowRemoteClients = true
	if !acceptClient(remote) {
		t.Fatal("remote clients must be served once explicitly allowed")
	}
}

func TestEnforceRemotePolicy(t *testing.T) {
	t.Chdir(t.TempDir())
	resetEnv(t, nil, nil)
	configuration.Address = "127.0.0.1:3128"
	enforceRemotePolicy()
	if configuration.AllowRemoteClients {
		t.Fatal("loopback configuration must stay restricted")
	}
	configuration.Address = "0.0.0.0:3128"
	enforceRemotePolicy()
	if !configuration.AllowRemoteClients {
		t.Fatal("an existing non-loopback setup keeps working after the upgrade")
	}
}

func TestValidateListenAddress(t *testing.T) {
	good := []string{"127.0.0.1:3128", "localhost:8080", "[::1]:3128", ":3128", "0.0.0.0:80", "my-host.local:3128"}
	bad := []string{"", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:99999", "127.0.0.1:abc", "evil host:80", "a\nb:80", "127.0.0.1\nd.add X:80", "h;rm:80", `h"x:80`}
	for _, a := range good {
		if err := validateListenAddress(a, false); err != nil {
			t.Errorf("%q rejected: %v", a, err)
		}
	}
	for _, a := range bad {
		if err := validateListenAddress(a, false); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
	if err := validateListenAddress("", true); err != nil {
		t.Errorf("empty must be allowed when optional: %v", err)
	}
}

func TestSaveConfigRefusesUnsafeAddresses(t *testing.T) {
	resetEnv(t, nil, nil)
	configuration.Address = "127.0.0.1:3128"
	post := func(body string) int {
		r := httptest.NewRequest("POST", "/api/config", strings.NewReader(body))
		w := httptest.NewRecorder()
		apiSaveConfig(w, r)
		return w.Code
	}
	for _, body := range []string{
		`{"address":"0.0.0.0:3128"}`,
		`{"address":"127.0.0.1:3128","socksAddress":":1080"}`,
		"{\"address\":\"127.0.0.1\\nd.add HTTPProxy evil:3128\"}",
		`{"address":"127.0.0.1:3128","allowRemoteClients":false,"socksAddress":"192.168.1.5:1080"}`,
	} {
		if code := post(body); code != http.StatusBadRequest {
			t.Errorf("%s -> %d, want 400", body, code)
		}
	}
	if configuration.Address != "127.0.0.1:3128" || configuration.SocksAddress != "" {
		t.Fatalf("rejected requests must not change the configuration: %q %q", configuration.Address, configuration.SocksAddress)
	}
}

func TestSafeConfigToken(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "3128", "ABCDEF-1234-5678", "::1", "host_name.local"} {
		if !safeConfigToken(s) {
			t.Errorf("%q should be safe", s)
		}
	}
	for _, s := range []string{"", "a b", "a\nb", "a;b", `a"b`, "a$b", "a`b", "a/b"} {
		if safeConfigToken(s) {
			t.Errorf("%q must be unsafe", s)
		}
	}
}

func TestRelayApprovalFlood(t *testing.T) {
	c := &relayClient{approvals: map[int64]*relayApproval{}}
	for i := int64(1); i <= relayMaxPendingPerFrom; i++ {
		c.approvals[i] = &relayApproval{ID: i, From: "mallory@example.com"}
	}
	if c.authorize("mallory@example.com", "d", "internal.example", 443) {
		t.Fatal("flooding contact must be refused immediately")
	}
	if len(c.approvals) != relayMaxPendingPerFrom {
		t.Fatalf("refused request must not be queued, have %d", len(c.approvals))
	}
}
