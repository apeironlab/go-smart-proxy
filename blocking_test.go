package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxy/blocklist"
	"proxy/relay"
)

// blockingEnv gives the engine a clean state, a cache in a temporary
// directory and a list server.
func blockingEnv(t *testing.T) (list *httptest.Server, fetches *atomic.Int32) {
	t.Helper()
	resetEnv(t, nil, nil)
	relayHub.reset()
	fetches = &atomic.Int32{}
	list = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		switch r.URL.Path {
		case "/ads":
			io.WriteString(w, "# ads\n0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n")
		case "/org":
			io.WriteString(w, "0.0.0.0 corp-blocked.example.org\n")
		case "/optional":
			io.WriteString(w, "0.0.0.0 advice.example.org\n")
		default:
			http.NotFound(w, r)
		}
	}))
	old := blocker
	blocker = &blockEngine{fetcher: &blocklist.Fetcher{Dir: t.TempDir()}, bySrc: map[string]int{}, byHost: map[string]int{}}
	t.Cleanup(func() {
		list.Close()
		blocker = old
		relayHub.reset()
	})
	return list, fetches
}

func setRelayPolicy(t *testing.T, name string, p *relay.PolicyPush) {
	t.Helper()
	c := newRelayClient(name)
	c.mu.Lock()
	c.state.Policy = p
	c.mu.Unlock()
	relayHub.put(name, c)
}

func TestBlockingConfigIsChecked(t *testing.T) {
	good := BlockingConfig{
		Enabled: true, Presets: []string{"stevenblack", "stevenblack"},
		Lists: []BlockList{{Name: "mine", URL: "https://example.com/list", Format: "hosts", Enabled: true}},
		Block: []string{"Ads.Example.com", "203.0.113.0/24", "198.51.100.7"}, Allow: []string{"ok.example.com"},
	}
	if err := good.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(good.Presets) != 1 || good.Block[0] != "ads.example.com" || good.Block[1] != "203.0.113.0/24" {
		t.Fatalf("not normalized: %+v", good)
	}
	bad := map[string]func(c *BlockingConfig){
		"preset":    func(c *BlockingConfig) { c.Presets = []string{"nope"} },
		"scheme":    func(c *BlockingConfig) { c.Lists[0].URL = "file:///etc/passwd" },
		"no name":   func(c *BlockingConfig) { c.Lists[0].Name = "" },
		"format":    func(c *BlockingConfig) { c.Lists[0].Format = "xml" },
		"duplicate": func(c *BlockingConfig) { c.Lists = append(c.Lists, c.Lists[0]) },
		"host":      func(c *BlockingConfig) { c.Block = []string{"not a host"} },
		"allow ip":  func(c *BlockingConfig) { c.Allow = []string{"10.0.0.0/8"} },
		"interval":  func(c *BlockingConfig) { c.RefreshHours = 99999 },
	}
	for name, mod := range bad {
		c := BlockingConfig{Lists: []BlockList{{Name: "mine", URL: "https://example.com/list", Enabled: true}}}
		mod(&c)
		if c.Normalize() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestUserListsCustomHostsAndAllowList(t *testing.T) {
	list, _ := blockingEnv(t)
	blocker.setConfig(BlockingConfig{
		Enabled: true,
		Lists:   []BlockList{{Name: "ads", URL: list.URL + "/ads", Format: "hosts", Enabled: true}, {Name: "off", URL: list.URL + "/optional", Format: "hosts", Enabled: false}},
		Block:   []string{"custom.example.com", "203.0.113.0/24"},
		Allow:   []string{"tracker.example.net"},
	})
	blocker.update(context.Background())

	expect := func(host string, blocked bool, source string) {
		t.Helper()
		d := blocker.check(host)
		if d.Blocked != blocked || (blocked && d.Hit.Source != source) {
			t.Errorf("%s: %+v (want blocked=%v by %q)", host, d, blocked, source)
		}
	}
	expect("ads.example.com", true, "ads")
	expect("img.ads.example.com", true, "ads")
	expect("custom.example.com", true, "your own list")
	expect("203.0.113.5", true, "your own list")
	expect("tracker.example.net", false, "") // on the list, but allowed
	expect("advice.example.org", false, "")  // a list that is off
	expect("example.com", false, "")

	// switching blocking off lets everything through
	c := blocker.config()
	c.Enabled = false
	blocker.setConfig(c)
	blocker.reload()
	expect("ads.example.com", false, "")

	// status shows what was downloaded
	c.Enabled = true
	blocker.setConfig(c)
	blocker.reload()
	if len(blocker.status) != 1 || blocker.status[0].Entries != 2 || blocker.status[0].Error != "" {
		t.Fatalf("status: %+v", blocker.status)
	}
}

func TestOrganizationRulesCannotBeSwitchedOffOrAllowed(t *testing.T) {
	list, _ := blockingEnv(t)
	setRelayPolicy(t, "corp", &relay.PolicyPush{
		Rev: "1",
		Rules: []relay.PolicyRule{
			{ID: "social", Name: "Social networks", Mandatory: true, Domains: []string{"social.example.com"}, Nets: []string{"198.51.100.0/24"}},
			{ID: "ads", Name: "Ads (advice)", Domains: []string{"ads-advice.example.com"}},
		},
		Lists: []relay.PolicyList{
			{ID: "org", Name: "Malware", URL: list.URL + "/org", Format: "hosts", Mandatory: true},
			{ID: "opt", Name: "Optional", URL: list.URL + "/optional", Format: "hosts"},
		},
		Allow: []string{"false-positive.corp-blocked.example.org"},
	})
	// the user allows everything they can and turns blocking off
	blocker.setConfig(BlockingConfig{Enabled: false, Allow: []string{"social.example.com", "corp-blocked.example.org"}})
	blocker.update(context.Background())

	for _, h := range []string{"social.example.com", "x.social.example.com", "198.51.100.9", "corp-blocked.example.org", "www.corp-blocked.example.org"} {
		d := blocker.check(h)
		if !d.Blocked || !d.Mandatory || d.Hit.Source != orgSource {
			t.Errorf("%s: %+v", h, d)
		}
	}
	// the relay's own allow list lifts its rules for that host
	if d := blocker.check("false-positive.corp-blocked.example.org"); d.Blocked {
		t.Fatalf("relay allow list ignored: %+v", d)
	}
	// recommended rules do nothing while the user's blocking is off ...
	if d := blocker.check("ads-advice.example.com"); d.Blocked {
		t.Fatalf("recommended rule applied with blocking off: %+v", d)
	}
	// ... apply when it is on, and the user can switch each one off
	blocker.setConfig(BlockingConfig{Enabled: true})
	blocker.reload()
	for _, h := range []string{"ads-advice.example.com", "advice.example.org"} {
		if d := blocker.check(h); !d.Blocked || d.Mandatory {
			t.Errorf("%s recommended: %+v", h, d)
		}
	}
	blocker.setConfig(BlockingConfig{Enabled: true, RelayOff: []string{"corp/ads", "corp/opt"}})
	blocker.reload()
	for _, h := range []string{"ads-advice.example.com", "advice.example.org"} {
		if d := blocker.check(h); d.Blocked {
			t.Errorf("%s still blocked after the user turned it off", h)
		}
	}
	// but the mandatory ones are not on offer: RelayOff names them in vain
	blocker.setConfig(BlockingConfig{Enabled: true, RelayOff: []string{"corp/social", "corp/org"}})
	blocker.reload()
	if d := blocker.check("social.example.com"); !d.Blocked || !d.Mandatory {
		t.Fatalf("a mandatory rule was switched off: %+v", d)
	}
}

func TestPublishedApplicationsAreNeverBlocked(t *testing.T) {
	blockingEnv(t)
	setRelayPolicy(t, "corp", &relay.PolicyPush{Rev: "1", Rules: []relay.PolicyRule{{ID: "all", Name: "All", Mandatory: true, Domains: []string{"apps.example.com"}}}})
	blocker.setConfig(BlockingConfig{Enabled: true})
	blocker.reload()
	if d := blocker.check("crm.apps.example.com"); !d.Blocked {
		t.Fatal("rule not applied")
	}
	c := newRelayClient("apps")
	c.mu.Lock()
	c.state.Apps = []relay.AppInfo{{ID: "crm", Name: "CRM", Host: "crm.apps.example.com", Kind: "http", Online: true}}
	c.mu.Unlock()
	relayHub.put("apps", c)
	if d := blocker.check("crm.apps.example.com"); d.Blocked {
		t.Fatalf("an application the relay publishes was blocked: %+v", d)
	}
}

func TestBlockedConnectionsAreRefusedAndCounted(t *testing.T) {
	blockingEnv(t)
	blocker.setConfig(BlockingConfig{Enabled: true, Block: []string{"ads.example.com"}})
	blocker.reload()

	// CONNECT / SOCKS go through dialTarget
	_, _, rec, err := dialTarget("tunnel", "127.0.0.1:5555", "x.ads.example.com", "443", "CONNECT", "")
	var be *blockedError
	if !errors.As(err, &be) || rec != nil || be.Host != "x.ads.example.com" || be.Mandatory {
		t.Fatalf("dialTarget: %v %v", err, rec)
	}
	// plain HTTP through the proxy
	req := httptest.NewRequest("GET", "http://ads.example.com/banner.js", nil)
	req.Host = "ads.example.com"
	w := httptest.NewRecorder()
	proxyHandler(w, req)
	if w.Code != 403 || w.Header().Get("X-Blocked-By") == "" || !strings.Contains(w.Body.String(), "Blocked") {
		t.Fatalf("http: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	st := blocker.stats()
	if st.Total != 2 || st.BySrc["your own list"] != 2 || len(st.Top) != 2 || len(st.Recent) != 2 || st.Recent[0].Host != "ads.example.com" {
		t.Fatalf("stats: %+v", st)
	}
	// the connections page shows them
	found := false
	for _, c := range connReg.list(true) {
		if c.State == StateBlocked && strings.Contains(c.Error, "blocked") {
			found = true
		}
	}
	if !found {
		t.Fatal("blocked connections are not in the connections list")
	}
	blocker.resetStats()
	if blocker.stats().Total != 0 {
		t.Fatal("stats not reset")
	}
}

func TestBlockingAPI(t *testing.T) {
	list, _ := blockingEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	oldConfig := configuration
	t.Cleanup(func() { configuration = oldConfig; clearConfigCrypto() })
	t.Setenv(secretEnv, "test-master-password")
	t.Setenv(noKeychainEnv, "1")
	enc, _ := encryptSecret("test-master-password", []byte("Address: 127.0.0.1:9999\nRoutes: []\n"))
	writeSecretFileAtomic(encryptedConfig, enc)
	loadConfiguration()

	call := func(method, path string, body any) (int, []byte) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req := httptest.NewRequest(method, path, rd)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		apiMux.ServeHTTP(w, req)
		return w.Code, w.Body.Bytes()
	}
	code, raw := call("GET", "/api/blocking", nil)
	var got struct {
		Config  BlockingConfig `json:"config"`
		Presets []presetJSON   `json:"presets"`
		Relays  []relayBlockJSON
	}
	if json.Unmarshal(raw, &got); code != 200 || len(got.Presets) != len(blockPresets) || got.Config.Enabled {
		t.Fatalf("get: %d %s", code, raw)
	}
	if strings.Contains(string(raw), "null") {
		t.Fatalf("the API sends null where arrays are expected: %s", raw)
	}

	save := BlockingConfig{Enabled: true, Lists: []BlockList{{Name: "ads", URL: list.URL + "/ads", Format: "hosts", Enabled: true}}, Block: []string{"x.example.com"}}
	if code, raw := call("PUT", "/api/blocking", save); code != 200 {
		t.Fatalf("put: %d %s", code, raw)
	}
	// it was written to the encrypted configuration
	if configuration.Blocking.Enabled != true || len(configuration.Blocking.Lists) != 1 {
		t.Fatalf("configuration: %+v", configuration.Blocking)
	}
	if b, _ := os.ReadFile(encryptedConfig); bytes.Contains(b, []byte("x.example.com")) {
		t.Fatal("the configuration is not encrypted")
	}
	if code, _ := call("PUT", "/api/blocking", BlockingConfig{Lists: []BlockList{{Name: "bad", URL: "file:///etc/hosts"}}}); code != 400 {
		t.Fatalf("a bad list was accepted: %d", code)
	}
	// the test endpoint explains
	blocker.update(context.Background())
	_, raw = call("GET", "/api/blocking/test?host=sub.ads.example.com:443", nil)
	var tst struct {
		Blocked bool
		Source  string
		Rule    string
	}
	json.Unmarshal(raw, &tst)
	if !tst.Blocked || tst.Source != "ads" || tst.Rule != "ads.example.com" {
		t.Fatalf("test: %s", raw)
	}
	// ... without revealing what the organization blocks
	setRelayPolicy(t, "corp", &relay.PolicyPush{Rev: "1", Rules: []relay.PolicyRule{{ID: "s", Name: "Secret rule name", Mandatory: true, Domains: []string{"secret.example.com"}}}})
	blocker.reload()
	_, raw = call("GET", "/api/blocking/test?host=secret.example.com", nil)
	if strings.Contains(string(raw), "Secret rule") || strings.Contains(string(raw), "\"rule\"") || !strings.Contains(string(raw), "organization") {
		t.Fatalf("the organization's rule is shown: %s", raw)
	}
	_, raw = call("GET", "/api/blocking", nil)
	if strings.Contains(string(raw), "Secret rule") || strings.Contains(string(raw), "secret.example.com") {
		t.Fatalf("the page shows the organization's rules: %s", raw)
	}
	var page struct{ Relays []relayBlockJSON }
	json.Unmarshal(raw, &page)
	if len(page.Relays) != 1 || page.Relays[0].Mandatory != 1 || len(page.Relays[0].Recommended) != 0 {
		t.Fatalf("relays: %s", raw)
	}
	if code, _ := call("GET", "/api/blocking/test", nil); code != 400 {
		t.Fatalf("test without a host: %d", code)
	}
}

func TestRelayPolicyChangeTriggersAFetch(t *testing.T) {
	list, fetches := blockingEnv(t)
	blocker.setConfig(BlockingConfig{})
	setRelayPolicy(t, "corp", &relay.PolicyPush{Rev: "1", Lists: []relay.PolicyList{{ID: "org", Name: "Org", URL: list.URL + "/org", Format: "hosts", Mandatory: true}}})
	blockingRelayState("corp", relayPolicies()["corp"])
	waitFor(t, "list downloaded", func() bool { return fetches.Load() >= 1 && blocker.check("corp-blocked.example.org").Blocked })
	n := fetches.Load()
	blockingRelayState("corp", relayPolicies()["corp"]) // same revision: nothing to do
	if fetches.Load() != n {
		t.Fatal("an unchanged policy was fetched again")
	}
}

func TestBlockedOverSOCKSAndCONNECT(t *testing.T) {
	blockingEnv(t)
	blocker.setConfig(BlockingConfig{Enabled: true, Block: []string{"ads.example.com"}})
	blocker.reload()

	// SOCKS5: reply 0x02, "connection not allowed by ruleset"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSOCKS(c)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(c, make([]byte, 2))
	host := "ads.example.com"
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	c.Write(append(req, 0x01, 0xbb))
	resp := make([]byte, 4)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0x02 {
		t.Fatalf("socks reply: %v %v", resp, err)
	}

	// HTTP CONNECT: 403
	addr := startOurProxy(t)
	pc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(pc, "CONNECT ads.example.com:443 HTTP/1.1\r\nHost: ads.example.com:443\r\n\r\n")
	line, _ := bufio.NewReader(pc).ReadString('\n')
	if !strings.Contains(line, "403") {
		t.Fatalf("CONNECT answer: %q", line)
	}
}
