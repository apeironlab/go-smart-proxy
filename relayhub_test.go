package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/apeironlab/go-smart-proxy/relay"
)

// testRelayServer is a real relay server for tests, with its own CA.
type testRelayServer struct {
	addr  string
	dir   string
	caPEM string
}

func startTestRelayServer(t *testing.T, users ...string) *testRelayServer {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	if err := relay.InitCA(ca); err != nil {
		t.Fatal(err)
	}
	if err := relay.IssueServer(ca, filepath.Join(dir, "srv"), []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range users {
		if err := relay.IssueClient(ca, filepath.Join(dir, e), e); err != nil {
			t.Fatal(err)
		}
	}
	tlsCfg, err := relay.TLSConfig(filepath.Join(dir, "srv", "server.pem"), filepath.Join(dir, "srv", "server-key.pem"), filepath.Join(ca, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := relay.NewStore("")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go relay.NewServer(store).Serve(ln)
	caPEM, err := os.ReadFile(filepath.Join(ca, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return &testRelayServer{addr: ln.Addr().String(), dir: dir, caPEM: string(caPEM)}
}

// client connects email to this server as a relay called name.
func (s *testRelayServer) client(t *testing.T, name, email string, allowLocal bool) *relayClient {
	t.Helper()
	certPEM, err := os.ReadFile(filepath.Join(s.dir, email, "client.pem"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(s.dir, email, "client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	c := newRelayClient(name)
	c.file = filepath.Join(t.TempDir(), name+"-"+email+".json")
	c.start(&RelayConfig{
		Name: name, Address: s.addr, CertPEM: string(certPEM), KeyPEM: string(keyPEM), CAPEM: s.caPEM,
		AllowLocal: allowLocal, Device: "dev-" + name,
	})
	t.Cleanup(c.stop)
	return c
}

// autoApprove answers every route request of an exit client with "allow".
func autoApprove(t *testing.T, c *relayClient) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(30 * time.Millisecond):
			}
			for _, a := range c.Status().Approvals {
				c.Decide(a.ID, relayDecision{Allow: true})
			}
		}
	}()
}

func befriendClients(t *testing.T, a, b *relayClient, aEmail, bEmail string) {
	t.Helper()
	if err := a.send(relay.ClientMsg{T: relay.TContactRequest, Email: bEmail}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "incoming request", func() bool { return len(b.Status().Incoming) == 1 })
	b.send(relay.ClientMsg{T: relay.TContactRespond, Email: aEmail, Accept: true})
	waitFor(t, "contacts", func() bool { return len(a.Status().Contacts) == 1 && len(b.Status().Contacts) == 1 })
}

func echoServer(t *testing.T) string {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return echo.Addr().String()
}

func roundTrip(t *testing.T, relayName, email, target string) error {
	t.Helper()
	conn, err := relayHub.Dial(relayName, email, "", target)
	if err != nil {
		return err
	}
	defer conn.Close()
	io.WriteString(conn, "hello")
	buf := make([]byte, 5)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo through %s: %q %v", email, buf, err)
	}
	return nil
}

func TestTwoRelaysEndToEnd(t *testing.T) {
	resetEnv(t, nil, nil)
	target := echoServer(t)
	office := startTestRelayServer(t, "alice@example.com", "bob@example.com")
	partner := startTestRelayServer(t, "alice@example.com", "carol@example.com", "bob@example.com")

	aliceOffice := office.client(t, "office", "alice@example.com", false)
	alicePartner := partner.client(t, "partner", "alice@example.com", false)
	bob := office.client(t, "office", "bob@example.com", true)
	carol := partner.client(t, "partner", "carol@example.com", true)
	autoApprove(t, bob)
	autoApprove(t, carol)

	relayHub.reset()
	relayHub.put("office", aliceOffice)
	relayHub.put("partner", alicePartner)
	t.Cleanup(relayHub.reset)

	waitFor(t, "alice connected to both relays", func() bool {
		return aliceOffice.Status().Connected && alicePartner.Status().Connected && bob.Status().Connected && carol.Status().Connected
	})
	befriendClients(t, aliceOffice, bob, "alice@example.com", "bob@example.com")
	befriendClients(t, alicePartner, carol, "alice@example.com", "carol@example.com")

	// Each contact is only known on one relay: a hop that does not name the
	// relay still finds the right one.
	if c, err := relayHub.forContact("", "bob@example.com", ""); err != nil || c.name != "office" {
		t.Fatalf("bob lives on the office relay: %v %v", c, err)
	}
	if c, err := relayHub.forContact("", "carol@example.com", ""); err != nil || c.name != "partner" {
		t.Fatalf("carol lives on the partner relay: %v %v", c, err)
	}
	if err := roundTrip(t, "", "bob@example.com", target); err != nil {
		t.Fatalf("through bob on the office relay: %v", err)
	}
	if err := roundTrip(t, "", "carol@example.com", target); err != nil {
		t.Fatalf("through carol on the partner relay: %v", err)
	}

	// Naming the wrong relay is refused, not silently redirected.
	if err := roundTrip(t, "partner", "bob@example.com", target); err == nil {
		t.Fatal("bob is not a contact on the partner relay")
	}
	if _, err := relayHub.forContact("nowhere", "bob@example.com", ""); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unknown relay name: %v", err)
	}

	// The two address books are separate.
	if len(aliceOffice.Status().Contacts) != 1 || aliceOffice.Status().Contacts[0].Email != "bob@example.com" {
		t.Fatalf("office address book: %+v", aliceOffice.Status().Contacts)
	}
	if len(alicePartner.Status().Contacts) != 1 || alicePartner.Status().Contacts[0].Email != "carol@example.com" {
		t.Fatalf("partner address book: %+v", alicePartner.Status().Contacts)
	}

	// Bob also joins the partner relay and befriends alice there: now the
	// plain hop is ambiguous and must name the relay.
	bobPartner := partner.client(t, "partner", "bob@example.com", true)
	autoApprove(t, bobPartner)
	waitFor(t, "bob connected to partner", func() bool { return bobPartner.Status().Connected })
	if err := alicePartner.send(relay.ClientMsg{T: relay.TContactRequest, Email: "bob@example.com"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "incoming request on partner", func() bool { return len(bobPartner.Status().Incoming) == 1 })
	bobPartner.send(relay.ClientMsg{T: relay.TContactRespond, Email: "alice@example.com", Accept: true})
	waitFor(t, "bob known on both", func() bool { return len(alicePartner.Status().Contacts) == 2 })

	_, err := relayHub.forContact("", "bob@example.com", "")
	if err == nil || !strings.Contains(err.Error(), "several relays") || !strings.Contains(err.Error(), "office") || !strings.Contains(err.Error(), "partner") {
		t.Fatalf("an ambiguous hop must say so and list the relays: %v", err)
	}
	if err := roundTrip(t, "office", "bob@example.com", target); err != nil {
		t.Fatalf("explicit office: %v", err)
	}
	if err := roundTrip(t, "partner", "bob@example.com", target); err != nil {
		t.Fatalf("explicit partner: %v", err)
	}
}

func TestExitConditionsUseTheRelayOfTheHop(t *testing.T) {
	office := newRelayClient("office")
	office.state = bobState(map[string]relay.NetContext{"laptop": {Label: "office-vpn", VPN: true}}, true, "laptop")
	partner := newRelayClient("partner")
	partner.state = bobState(map[string]relay.NetContext{"laptop": {Label: "home", VPN: false}}, true, "laptop")
	relayHub.reset()
	relayHub.put("office", office)
	relayHub.put("partner", partner)
	t.Cleanup(relayHub.reset)

	// the same contact is on both relays, on a VPN on one and not on the other
	for _, c := range []struct {
		hop, vpn string
		want     bool
	}{
		{"relay://bob@example.com/laptop?relay=office", "up", true},
		{"relay://bob@example.com/laptop?relay=office", "down", false},
		{"relay://bob@example.com/laptop?relay=partner", "up", false},
		{"relay://bob@example.com/laptop?relay=partner", "down", true},
	} {
		got, why := relayRoute(t, "r", c.hop, c.vpn, "").applicable(netState{})
		if got != c.want {
			t.Errorf("%s with exit VPN %s: applicable=%v (%s), want %v", c.hop, c.vpn, got, why, c.want)
		}
	}
	// without a relay name the hop cannot tell which one is meant
	if ok, why := relayRoute(t, "r", "relay://bob@example.com/laptop", "up", "").applicable(netState{}); ok || !strings.Contains(why, "several relays") {
		t.Fatalf("ambiguous hop: %v %q", ok, why)
	}
}

func TestRelayHopNames(t *testing.T) {
	h, err := buildChain([]ConfigHop{{ProxyUrl: "relay://bob@example.com/laptop?relay=Office"}})
	if err != nil {
		t.Fatal(err)
	}
	if h[0].relayName != "office" || h[0].addr != "bob@example.com" || h[0].device != "laptop" {
		t.Fatalf("hop: %+v", h[0])
	}
	if got := chainLabel(h); got != "bob@example.com/laptop @office" {
		t.Fatalf("label: %q", got)
	}
	if _, err := buildChain([]ConfigHop{{ProxyUrl: "relay://bob@example.com?relay=Bad Name!"}}); err == nil {
		t.Fatal("invalid relay name must be rejected")
	}
	plain, _ := buildChain([]ConfigHop{{ProxyUrl: "relay://bob@example.com"}})
	if plain[0].relayName != "" {
		t.Fatal("no name means: the relay that knows the contact")
	}
}

func TestForContactWithOneOrNoRelay(t *testing.T) {
	relayHub.reset()
	t.Cleanup(relayHub.reset)
	if _, err := relayHub.forContact("", "bob@example.com", ""); err == nil {
		t.Fatal("no relay at all")
	}
	only := newRelayClient("default")
	relayHub.put("default", only)
	if c, err := relayHub.forContact("", "anyone@example.com", ""); err != nil || c != only {
		t.Fatalf("with a single relay every hop uses it, as before: %v %v", c, err)
	}
	relayHub.put("second", newRelayClient("second"))
	if _, err := relayHub.forContact("", "stranger@example.com", ""); err == nil || !strings.Contains(err.Error(), "not a contact on any relay") {
		t.Fatalf("a contact nobody knows: %v", err)
	}
}

func TestRelayNamesAndStateFiles(t *testing.T) {
	for _, ok := range []string{"office", "partner-2", "a_b", "default", "0day"} {
		if !validRelayName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "Office", "has space", "-lead", "a/b", "../x", strings.Repeat("a", 31), "dot.name"} {
		if validRelayName(bad) {
			t.Errorf("%q must be invalid", bad)
		}
	}
	if f := newRelayClient("default").stateFile(); f != relayStateFile {
		t.Errorf("the migrated relay keeps its historical file, got %q", f)
	}
	if f := newRelayClient("office").stateFile(); f != "relay_state.office.json" {
		t.Errorf("a named relay gets its own file, got %q", f)
	}
}

func TestMigrateRelayConfigs(t *testing.T) {
	old := configuration
	t.Cleanup(func() { configuration = old })

	configuration = Configuration{Relay: &RelayConfig{Address: "r.example:8443", Device: "my-pc"}}
	if !migrateRelayConfigs() {
		t.Fatal("a legacy relay must be migrated")
	}
	if configuration.Relay != nil || len(configuration.Relays) != 1 || configuration.Relays[0].Name != "default" || configuration.Relays[0].Address != "r.example:8443" {
		t.Fatalf("migration: %+v / %+v", configuration.Relay, configuration.Relays)
	}
	if migrateRelayConfigs() {
		t.Fatal("a second pass must change nothing")
	}

	configuration = Configuration{Relays: []*RelayConfig{
		{Name: "office"}, {Name: "office"}, {Name: "Bad Name"}, {},
	}}
	if !migrateRelayConfigs() {
		t.Fatal("duplicate and invalid names must be repaired")
	}
	seen := map[string]bool{}
	for _, c := range configuration.Relays {
		if !validRelayName(c.Name) || seen[c.Name] {
			t.Fatalf("names must be valid and unique: %+v", configuration.Relays)
		}
		seen[c.Name] = true
	}
	if configuration.Relays[0].Name != "office" {
		t.Fatal("the first of several equal names keeps it")
	}
}

func TestRelayConfigAPIAddsAndRemovesRelays(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(noKeychainEnv, "1")
	oldCfg := configuration
	t.Cleanup(func() { configuration = oldCfg; clearConfigCrypto(); relayHub.reset() })
	configuration = Configuration{}
	relayHub.reset()
	key := make([]byte, secretKeySize)
	salt := make([]byte, secretSaltSize)
	setConfigCrypto(key, salt)

	call := func(method, url, body string) (int, map[string]any) {
		r := httptest.NewRequest(method, url, strings.NewReader(body))
		w := httptest.NewRecorder()
		apiMux.ServeHTTP(w, r)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	callList := func(url string) (int, []map[string]any) {
		r := httptest.NewRequest("GET", url, nil)
		w := httptest.NewRecorder()
		apiMux.ServeHTTP(w, r)
		var out []map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	// no relay yet: the page still gets a status to show the enrollment form
	if code, out := call("GET", "/api/relay", ""); code != 200 || out["enabled"] != false {
		t.Fatalf("no relay: %d %v", code, out)
	}
	if code, list := callList("/api/relays"); code != 200 || len(list) != 0 {
		t.Fatalf("no relays: %d %v", code, list)
	}

	if code, out := call("POST", "/api/relay/config", `{"name":"office","address":"127.0.0.1:1"}`); code != 200 || out["name"] != "office" {
		t.Fatalf("first relay: %d %v", code, out)
	}
	code, out := call("POST", "/api/relay/config", `{"name":"partner","address":"127.0.0.1:2","networkLabel":"home"}`)
	if code != 200 || out["name"] != "partner" || out["networkLabel"] != "home" {
		t.Fatalf("second relay: %d %v", code, out)
	}
	configMu.Lock()
	first, second := configuration.Relays[0], configuration.Relays[1]
	configMu.Unlock()
	if first.Device == "" || first.Device != second.Device {
		t.Fatalf("your devices keep the same name on every relay: %q %q", first.Device, second.Device)
	}

	if code, list := callList("/api/relays/config"); code != 200 || len(list) != 2 || list[0]["name"] != "office" || list[1]["name"] != "partner" {
		t.Fatalf("configs: %d %v", code, list)
	}
	if code, list := callList("/api/relays"); code != 200 || len(list) != 2 {
		t.Fatalf("statuses: %d %v", code, list)
	}
	if code, out := call("GET", "/api/relay?relay=partner", ""); code != 200 || out["name"] != "partner" {
		t.Fatalf("select by name: %d %v", code, out)
	}
	if code, out := call("GET", "/api/relay", ""); code != 200 || out["name"] != "office" {
		t.Fatalf("the first relay is the default: %d %v", code, out)
	}
	if code, _ := call("GET", "/api/relay?relay=nope", ""); code != 404 {
		t.Fatalf("unknown relay: %d", code)
	}
	if code, _ := call("POST", "/api/relay/contacts?relay=nope", `{"email":"a@example.com"}`); code != 404 {
		t.Fatalf("a command for an unknown relay: %d", code)
	}

	// updating by name changes that relay only
	if code, _ := call("POST", "/api/relay/config", `{"name":"office","address":"127.0.0.1:3"}`); code != 200 {
		t.Fatal("update")
	}
	configMu.Lock()
	if len(configuration.Relays) != 2 || configuration.Relays[0].Address != "127.0.0.1:3" || configuration.Relays[1].Address != "127.0.0.1:2" {
		t.Fatalf("update by name: %+v %+v", configuration.Relays[0], configuration.Relays[1])
	}
	configMu.Unlock()

	if code, _ := call("POST", "/api/relay/config", `{"name":"Bad Name","address":"127.0.0.1:1"}`); code != 400 {
		t.Fatalf("invalid name: %d", code)
	}
	for i := 3; i <= maxRelays; i++ {
		call("POST", "/api/relay/config", `{"name":"r`+strconv.Itoa(i)+`","address":"127.0.0.1:1"}`)
	}
	if code, _ := call("POST", "/api/relay/config", `{"name":"onetoomany","address":"127.0.0.1:1"}`); code != 400 {
		t.Fatalf("too many relays: %d", code)
	}

	if code, _ := call("DELETE", "/api/relay/config", ""); code != 400 {
		t.Fatalf("removing without a name: %d", code)
	}
	if code, _ := call("DELETE", "/api/relay/config?relay=nope", ""); code != 404 {
		t.Fatalf("removing an unknown relay: %d", code)
	}
	if code, _ := call("DELETE", "/api/relay/config?relay=partner", ""); code != 200 {
		t.Fatal("remove")
	}
	configMu.Lock()
	for _, c := range configuration.Relays {
		if c.Name == "partner" {
			t.Fatal("the relay must leave the configuration")
		}
	}
	configMu.Unlock()
	if relayHub.get("partner") != nil || relayHub.get("office") == nil {
		t.Fatal("the removed relay must stop and the others stay")
	}
}

func TestRelaysSurviveTheConfigurationFile(t *testing.T) {
	share := false
	in := Configuration{Relays: []*RelayConfig{
		{Name: "office", Address: "a.example:8443", Device: "my-pc", NetworkLabel: "office-vpn",
			NetworkLabels: []NetworkLabel{{Label: "vpn", VPN: "up"}}},
		{Name: "partner", Address: "b.example:8443", Device: "my-pc", ShareContext: &share},
	}}
	data, err := yaml.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\nrelay:") {
		t.Fatalf("the legacy key must not be written back:\n%s", data)
	}
	var out Configuration
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Relays) != 2 || out.Relays[0].Name != "office" || out.Relays[1].Address != "b.example:8443" ||
		len(out.Relays[0].NetworkLabels) != 1 || out.Relays[1].ShareContext == nil || *out.Relays[1].ShareContext {
		t.Fatalf("round trip: %+v", out.Relays)
	}

	// a file written before multi-relay still loads
	var legacy Configuration
	if err := yaml.Unmarshal([]byte("Relay:\n  Address: old.example:8443\n  Device: my-pc\n"), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Relay == nil || legacy.Relay.Address != "old.example:8443" {
		t.Fatalf("legacy file: %+v", legacy)
	}
}
