package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/expirablelru"
)

// apiFixture gives each test an empty configuration, a key to write it with
// and a clean set of routes.
func apiFixture(t *testing.T) func(method, url, body string) (int, map[string]any) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv(noKeychainEnv, "1")
	oldCfg, oldDNS := configuration, dnsCache
	t.Cleanup(func() {
		configuration, dnsCache = oldCfg, oldDNS
		clearConfigCrypto()
		setForceRoute(nil)
		loadRoutes()
	})
	configuration = Configuration{Address: "127.0.0.1:3128"}
	dnsCache = expirablelru.NewExpirableLRU(10, nil, time.Hour, time.Hour)
	setConfigCrypto(make([]byte, secretKeySize), make([]byte, secretSaltSize))
	loadRoutes()
	return func(method, url, body string) (int, map[string]any) {
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		w := httptest.NewRecorder()
		apiMux.ServeHTTP(w, r)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
}

func TestRouteAPI(t *testing.T) {
	call := apiFixture(t)

	for name, body := range map[string]string{
		"not json":    `{`,
		"no name":     `{"name":""}`,
		"bad hop":     `{"name":"a","hops":[{"proxyUrl":"::not a url"}]}`,
		"bad vpn":     `{"name":"a","vpn":"sideways"}`,
		"bad exitVpn": `{"name":"a","exitVpn":"sideways"}`,
		"bad label":   `{"name":"a","exitLabel":"[x"}`,
		"bad pattern": `{"name":"a","ifaceUp":"[x"}`,
	} {
		if code, _ := call("POST", "/api/routes", body); code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, code)
		}
	}

	save := `{"name":"office","gateway":"10.0.0.1","iface":"en*","net":"10.0.0.0/8","vpn":" UP ","hops":[{"proxyUrl":"http://proxy.example:8080"}]}`
	if code, _ := call("POST", "/api/routes", save); code != 200 {
		t.Fatalf("save: %d", code)
	}
	if code, _ := call("POST", "/api/routes", `{"name":"lab","hops":[{"proxyUrl":"http://lab.example:3128"}],"rulesOnly":true}`); code != 200 {
		t.Fatalf("save lab: %d", code)
	}
	// saving again replaces
	if code, _ := call("POST", "/api/routes", strings.Replace(save, "10.0.0.1", "10.0.0.2", 1)); code != 200 {
		t.Fatalf("resave: %d", code)
	}
	if len(configuration.Routes) != 2 || configuration.Routes[0].Gateway != "10.0.0.2" || configuration.Routes[0].VPN != "up" {
		t.Fatalf("routes = %+v", configuration.Routes)
	}

	r := httptest.NewRecorder()
	apiMux.ServeHTTP(r, httptest.NewRequest("GET", "/api/routes", nil))
	var list []map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &list); err != nil || len(list) != 3 { // two routes and Direct
		t.Fatalf("list: %v %d %s", err, len(list), r.Body.String())
	}

	// reordering
	for name, body := range map[string]string{
		"not json": `{`, "missing": `{"names":["lab"]}`, "unknown": `{"names":["lab","nope"]}`, "repeated": `{"names":["lab","lab"]}`,
	} {
		if code, _ := call("POST", "/api/routes/order", body); code != http.StatusBadRequest {
			t.Errorf("order %s: %d", name, code)
		}
	}
	if code, _ := call("POST", "/api/routes/order", `{"names":["lab","office"]}`); code != 200 {
		t.Fatalf("order: %d", code)
	}
	if configuration.Routes[0].Name != "lab" {
		t.Errorf("order not applied: %+v", configuration.Routes)
	}

	// forcing a route
	if code, _ := call("POST", "/api/force-route", `{`); code != http.StatusBadRequest {
		t.Errorf("force: %d", code)
	}
	if code, _ := call("POST", "/api/force-route", `{"name":"nope"}`); code != http.StatusNotFound {
		t.Errorf("force unknown: %d", code)
	}
	if code, _ := call("POST", "/api/force-route", `{"name":"lab"}`); code != http.StatusBadRequest {
		t.Errorf("a rules-only route was forced: %d", code)
	}
	if code, out := call("POST", "/api/force-route", `{"name":"office"}`); code != 200 || out["forceRoute"] != "office" {
		t.Errorf("force office: %d %v", code, out)
	}
	if code, out := call("POST", "/api/force-route", `{"name":""}`); code != 200 || out["forceRoute"] != "" {
		t.Errorf("unforce: %d %v", code, out)
	}

	// refreshing a PAC
	if code, _ := call("POST", "/api/pac/refresh", `{`); code != http.StatusBadRequest {
		t.Errorf("pac: %d", code)
	}
	if code, _ := call("POST", "/api/pac/refresh", `{"name":"nope"}`); code != http.StatusNotFound {
		t.Errorf("pac unknown: %d", code)
	}
	if code, _ := call("POST", "/api/pac/refresh", `{"name":"office"}`); code != 200 {
		t.Errorf("pac office: %d", code)
	}

	// deleting
	if code, _ := call("DELETE", "/api/routes/lab", ""); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if len(configuration.Routes) != 1 || configuration.Routes[0].Name != "office" {
		t.Errorf("routes after delete = %+v", configuration.Routes)
	}
}

func TestRouteAPILockedConfiguration(t *testing.T) {
	call := apiFixture(t)
	clearConfigCrypto() // the key is gone: nothing can be written
	if code, _ := call("POST", "/api/routes", `{"name":"a"}`); code != http.StatusInternalServerError {
		t.Errorf("save while locked: %d", code)
	}
	if code, _ := call("DELETE", "/api/routes/a", ""); code != http.StatusInternalServerError {
		t.Errorf("delete while locked: %d", code)
	}
	if code, _ := call("POST", "/api/credentials", `{"name":"a"}`); code != http.StatusInternalServerError {
		t.Errorf("credential while locked: %d", code)
	}
	if code, _ := call("DELETE", "/api/credentials/a", ""); code != http.StatusInternalServerError {
		t.Errorf("credential delete while locked: %d", code)
	}
	if code, _ := call("POST", "/api/onboarding", ""); code != http.StatusInternalServerError {
		t.Errorf("onboarding while locked: %d", code)
	}
	configuration.Routes = []ConfigRoute{{Name: "a"}, {Name: "b"}}
	if code, _ := call("POST", "/api/routes/order", `{"names":["b","a"]}`); code != http.StatusInternalServerError {
		t.Errorf("order while locked: %d", code)
	}
}

func TestCredentialAPI(t *testing.T) {
	call := apiFixture(t)
	if code, _ := call("POST", "/api/credentials", `{`); code != http.StatusBadRequest {
		t.Errorf("not json: %d", code)
	}
	if code, _ := call("POST", "/api/credentials", `{"user":"u"}`); code != http.StatusBadRequest {
		t.Errorf("no name: %d", code)
	}
	if code, _ := call("POST", "/api/credentials", `{"name":"corp","user":"ann","password":"s3cret"}`); code != 200 {
		t.Fatal(code)
	}
	// An empty password keeps the stored one; clearPassword removes it.
	call("POST", "/api/credentials", `{"name":"corp","user":"ann2"}`)
	if c := configuration.Credentials[0]; c.User != "ann2" || c.Password != "s3cret" {
		t.Errorf("credential = %+v", c)
	}
	call("POST", "/api/credentials", `{"name":"corp","user":"ann2","clearPassword":true}`)
	if configuration.Credentials[0].Password != "" {
		t.Error("the password was not cleared")
	}
	r := httptest.NewRecorder()
	apiMux.ServeHTTP(r, httptest.NewRequest("GET", "/api/credentials", nil))
	if strings.Contains(r.Body.String(), "s3cret") {
		t.Error("the password was sent to the interface")
	}
	if code, _ := call("DELETE", "/api/credentials/corp", ""); code != 200 || len(configuration.Credentials) != 0 {
		t.Errorf("delete: %d %v", code, configuration.Credentials)
	}
}

func TestConfigAPI(t *testing.T) {
	call := apiFixture(t)
	t.Setenv("HOME", t.TempDir())
	oldSys := configuration.SystemProxy
	_ = oldSys

	code, out := call("GET", "/api/config", "")
	if code != 200 || out["address"] != "127.0.0.1:3128" {
		t.Fatalf("get: %d %v", code, out)
	}
	for name, body := range map[string]string{
		"not json":     `{`,
		"bad address":  `{"address":"nonsense"}`,
		"bad socks":    `{"socksAddress":"nonsense"}`,
		"remote":       `{"address":"0.0.0.0:3128"}`,
		"remote socks": `{"socksAddress":"0.0.0.0:1080"}`,
		"bad hosts":    `{"hosts":{"nas":"not-an-ip"}}`,
		"host no addr": `{"hosts":{"":"10.0.0.1"}}`,
	} {
		if code, _ := call("POST", "/api/config", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	body := `{"hosts":{" NAS.Home ":"192.168.1.20","":""},"systemProxyExclude":["*.local"],"allowRemoteClients":false}`
	if code, _ := call("POST", "/api/config", body); code != 200 {
		t.Fatalf("save: %d", code)
	}
	if configuration.Hosts["nas.home"] != "192.168.1.20" || len(configuration.Hosts) != 1 {
		t.Errorf("hosts = %v", configuration.Hosts)
	}
	if len(configuration.SystemProxyExclude) != 1 {
		t.Errorf("exclude = %v", configuration.SystemProxyExclude)
	}
	// the setting of older versions is still accepted and ignored
	if code, _ := call("POST", "/api/config", `{"forceChrome":true,"systemProxy":false}`); code != 200 || configuration.ForceChrome {
		t.Errorf("legacy forceChrome: %d", code)
	}

	if code, _ := call("POST", "/api/onboarding", ""); code != 200 || configuration.OnboardingDone == nil || !*configuration.OnboardingDone {
		t.Errorf("onboarding: %d", code)
	}
	if code, _ := call("GET", "/api/system-proxy", ""); code != 200 {
		t.Errorf("system proxy: %d", code)
	}
	if code, _ := call("POST", "/api/connections/abc/close", ""); code != http.StatusBadRequest {
		t.Errorf("close with a bad id: %d", code)
	}
	if code, out := call("POST", "/api/connections/999999/close", ""); code != 200 || out["closed"] != false {
		t.Errorf("close unknown: %d %v", code, out)
	}
}

func TestLegacyChromePolicyIsRemovedOnce(t *testing.T) {
	apiFixture(t)
	removed := 0
	old := chromePolicyRemover
	chromePolicyRemover = func() { removed++ }
	defer func() { chromePolicyRemover = old }()

	removeLegacyChromePolicy() // nothing to undo
	if removed != 0 {
		t.Fatal("the policy was removed without the old setting")
	}
	configuration.ForceChrome = true
	removeLegacyChromePolicy()
	if removed != 1 || configuration.ForceChrome {
		t.Fatalf("removed %d times, ForceChrome %v", removed, configuration.ForceChrome)
	}
	removeLegacyChromePolicy() // the setting was forgotten: not again
	if removed != 1 {
		t.Fatalf("removed again: %d", removed)
	}
}
