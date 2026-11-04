package main

import (
	"net"
	"testing"

	"proxy/relay"
)

// setRelayState makes a single relay called "default" with the given address
// book, as the relay told us.
func setRelayState(t *testing.T, st relay.State, device string) {
	t.Helper()
	c := newRelayClient("default")
	c.state, c.device = st, device
	relayHub.reset()
	relayHub.put("default", c)
	t.Cleanup(relayHub.reset)
}

func bobState(ctx map[string]relay.NetContext, online bool, devices ...string) relay.State {
	return relay.State{
		Email: "me@example.com",
		Contacts: []relay.Contact{
			{Email: "bob@example.com", Online: online, Devices: devices, Context: ctx},
		},
	}
}

func relayRoute(t *testing.T, name, hop, vpn, label string) *ProxyRoute {
	t.Helper()
	r, err := newProxyRoute(&ConfigRoute{Name: name, Chain: []ConfigHop{{ProxyUrl: hop}}, ExitVPN: vpn, ExitLabel: label})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestExitConditions(t *testing.T) {
	setRelayState(t, bobState(map[string]relay.NetContext{
		"laptop": {Label: "office-vpn", VPN: true},
		"home":   {Label: "home", VPN: false},
	}, true, "laptop", "home"), "mine")

	cases := []struct {
		name, hop, vpn, label string
		want                  bool
	}{
		{"no conditions", "relay://bob@example.com/laptop", "", "", true},
		{"vpn up, device on vpn", "relay://bob@example.com/laptop", "up", "", true},
		{"vpn up, device not on vpn", "relay://bob@example.com/home", "up", "", false},
		{"vpn down, device not on vpn", "relay://bob@example.com/home", "down", "", true},
		{"vpn down, device on vpn", "relay://bob@example.com/laptop", "down", "", false},
		{"label exact", "relay://bob@example.com/laptop", "", "office-vpn", true},
		{"label glob", "relay://bob@example.com/laptop", "", "office*", true},
		{"label list", "relay://bob@example.com/home", "", "office*, home", true},
		{"label mismatch", "relay://bob@example.com/home", "", "office*", false},
		{"both", "relay://bob@example.com/laptop", "up", "office*", true},
		// no device chosen and two online: both must satisfy, because the relay
		// refuses to choose between them
		{"ambiguous exit, one fails", "relay://bob@example.com", "up", "", false},
		{"ambiguous exit, none required", "relay://bob@example.com", "", "", true},
		{"unknown contact", "relay://zed@example.com/x", "up", "", false},
	}
	for _, c := range cases {
		r := relayRoute(t, "r", c.hop, c.vpn, c.label)
		got, why := r.applicable(netState{})
		if got != c.want {
			t.Errorf("%s: applicable=%v (%s), want %v", c.name, got, why, c.want)
		}
		if !got && why == "" {
			t.Errorf("%s: a refusal must say why", c.name)
		}
	}
}

func TestExitConditionsNeedAnOnlineSharingExit(t *testing.T) {
	// offline
	setRelayState(t, bobState(nil, false), "mine")
	if ok, why := relayRoute(t, "r", "relay://bob@example.com", "up", "").applicable(netState{}); ok || why == "" {
		t.Fatalf("offline exit: %v %q", ok, why)
	}
	// online but sharing nothing: unknown is never treated as a match
	setRelayState(t, bobState(nil, true, "laptop"), "mine")
	if ok, why := relayRoute(t, "r", "relay://bob@example.com/laptop", "down", "").applicable(netState{}); ok || why == "" {
		t.Fatalf("exit that shares nothing: %v %q", ok, why)
	}
	// but without conditions the route stays usable
	if ok, _ := relayRoute(t, "r", "relay://bob@example.com/laptop", "", "").applicable(netState{}); !ok {
		t.Fatal("a route without exit conditions is unaffected")
	}
}

func TestExitConditionsOnRoutesWithoutRelay(t *testing.T) {
	r, err := newProxyRoute(&ConfigRoute{Name: "plain", Chain: []ConfigHop{{ProxyUrl: "http://proxy.example:8080"}}, ExitVPN: "up"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.applicable(netState{}); ok {
		t.Fatal("exit conditions on a route without relay hop can never hold")
	}
}

func TestExitConditionsOwnDevices(t *testing.T) {
	st := relay.State{Email: "me@example.com", MyDevices: []relay.DeviceInfo{
		{ID: "mine", Online: true},
		{ID: "office", Online: true, Context: &relay.NetContext{Label: "office-vpn", VPN: true}},
		{ID: "off", Online: false},
	}}
	setRelayState(t, st, "mine")
	if ok, why := relayRoute(t, "r", "relay://me@example.com/office", "up", "office*").applicable(netState{}); !ok {
		t.Fatalf("own device on a VPN: %s", why)
	}
}

func TestExitConditionValidation(t *testing.T) {
	if _, err := newProxyRoute(&ConfigRoute{Name: "x", ExitVPN: "maybe"}); err == nil {
		t.Fatal("invalid ExitVPN")
	}
	if _, err := newProxyRoute(&ConfigRoute{Name: "x", ExitLabel: "[bad"}); err == nil {
		t.Fatal("invalid ExitLabel glob")
	}
	if _, err := compileRule(ConfigRule{Name: "x", Hosts: []string{"a.example"}, Route: "r", ExitVPN: "maybe"}); err == nil {
		t.Fatal("invalid rule ExitVPN")
	}
	if _, err := compileRule(ConfigRule{Name: "x", Hosts: []string{"a.example"}, Route: "r", ExitLabel: "[bad"}); err == nil {
		t.Fatal("invalid rule ExitLabel")
	}
	r, err := compileRule(ConfigRule{Name: "x", Hosts: []string{"a.example"}, Route: "r", ExitVPN: " UP ", ExitLabel: " office* "})
	if err != nil || r.exitVPN != "up" || r.exitLabel != "office*" {
		t.Fatalf("normalization: %+v %v", r, err)
	}
}

func TestRuleExitConditionsFallThroughToNextRule(t *testing.T) {
	setRelayState(t, bobState(map[string]relay.NetContext{
		"laptop": {Label: "office-vpn", VPN: true},
		"home":   {Label: "home", VPN: false},
	}, true, "laptop", "home"), "mine")
	resetEnv(t, nil, []ConfigRoute{
		{Name: "Via office", Chain: []ConfigHop{{ProxyUrl: "relay://bob@example.com/laptop"}}, RulesOnly: true},
		{Name: "Via home", Chain: []ConfigHop{{ProxyUrl: "relay://bob@example.com/home"}}, RulesOnly: true},
	})
	rules, err := compileRules([]ConfigRule{
		// only while the exit is NOT on a VPN: bob's laptop is, so this must be skipped
		{Name: "Home first", Hosts: []string{"app.example"}, Route: "Via office", ExitVPN: "down"},
		{Name: "Office", Hosts: []string{"app.example"}, Route: "Via office", ExitVPN: "up", ExitLabel: "office*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rulesMu.Lock()
	old := routeRules
	routeRules = rules
	rulesMu.Unlock()
	t.Cleanup(func() { rulesMu.Lock(); routeRules = old; rulesMu.Unlock() })

	rt, rule := firstRuleRoute("app.example")
	if rt == nil || rule != "Office" || rt.name != "Via office" {
		t.Fatalf("got route=%v rule=%q, want the second rule", rt, rule)
	}

	// the laptop leaves its VPN: now the first rule matches
	setRelayState(t, bobState(map[string]relay.NetContext{
		"laptop": {Label: "office", VPN: false},
	}, true, "laptop"), "mine")
	rt, rule = firstRuleRoute("app.example")
	if rt == nil || rule != "Home first" {
		t.Fatalf("after leaving the VPN: route=%v rule=%q", rt, rule)
	}

	// and when the exit shares nothing, no rule with conditions applies
	setRelayState(t, bobState(nil, true, "laptop"), "mine")
	if rt, rule = firstRuleRoute("app.example"); rt != nil {
		t.Fatalf("unknown context must not match: %v %q", rt, rule)
	}
}

func TestSharedContext(t *testing.T) {
	yes, no := true, false
	rm := newRelayClient("default")
	save := func(rc *RelayConfig, vpn []string) {
		stateMu.Lock()
		analysis = netAnalysis{VPN: vpn}
		stateMu.Unlock()
		rm.mu.Lock()
		rm.cfg = rc
		rm.mu.Unlock()
	}
	t.Cleanup(func() {
		stateMu.Lock()
		analysis = netAnalysis{}
		stateMu.Unlock()
	})

	save(&RelayConfig{NetworkLabel: "office-vpn"}, []string{"utun4"})
	if c := rm.sharedContext(); c == nil || c.Label != "office-vpn" || !c.VPN {
		t.Fatalf("default is to share label and VPN: %+v", c)
	}
	save(&RelayConfig{NetworkLabel: "home"}, nil)
	if c := rm.sharedContext(); c == nil || c.VPN {
		t.Fatalf("no VPN: %+v", c)
	}
	save(&RelayConfig{NetworkLabel: "secret", ShareContext: &no}, []string{"utun4"})
	if c := rm.sharedContext(); c != nil {
		t.Fatalf("sharing off must share nothing: %+v", c)
	}
	save(&RelayConfig{ShareContext: &yes}, nil)
	if c := rm.sharedContext(); c == nil || c.Label != "" {
		t.Fatalf("no label chosen: only the VPN flag goes out: %+v", c)
	}
}

func netWith(vpn []string, defaultIface string, nets ...string) netState {
	st := netState{
		iface:       net.Interface{Name: defaultIface},
		analysis:    netAnalysis{VPN: vpn, Active: map[string]bool{defaultIface: true}},
		networkNets: map[string]bool{},
	}
	for _, v := range vpn {
		st.analysis.Active[v] = true
	}
	for _, n := range nets {
		st.networkNets[n] = true
	}
	return st
}

func TestLabelForNetwork(t *testing.T) {
	cfg := &RelayConfig{
		NetworkLabel: "elsewhere",
		NetworkLabels: []NetworkLabel{
			{Label: "office-vpn", VPN: "up", IFaceUp: "utun*"},
			{Label: "office-lan", Net: "10.20.0.0/16"},
			{Label: "home", VPN: "down", Net: "192.168.1.0/24"},
			{Label: "ignored-no-conditions"},
			{VPN: "up"}, // no label: skipped
		},
	}
	cases := []struct {
		name  string
		st    netState
		label string
		rule  int
	}{
		{"on the VPN", netWith([]string{"utun4"}, "en0", "192.168.1.0/24"), "office-vpn", 0},
		{"first match wins over a later one", netWith([]string{"utun4"}, "en0", "10.20.0.0/16"), "office-vpn", 0},
		{"on the office LAN", netWith(nil, "en0", "10.20.0.0/16"), "office-lan", 1},
		{"at home", netWith(nil, "en0", "192.168.1.0/24"), "home", 2},
		{"a VPN anywhere else", netWith([]string{"tun0"}, "wlan0", "172.16.0.0/12"), "elsewhere", -1},
		{"unknown network", netWith(nil, "en0", "172.16.0.0/12"), "elsewhere", -1},
	}
	for _, c := range cases {
		label, rule := labelForNetwork(cfg, c.st)
		if label != c.label || rule != c.rule {
			t.Errorf("%s: got %q (rule %d), want %q (rule %d)", c.name, label, rule, c.label, c.rule)
		}
	}
}

func TestSharedContextFollowsTheNetworkTable(t *testing.T) {
	cfg := &RelayConfig{NetworkLabel: "default", NetworkLabels: []NetworkLabel{{Label: "office-vpn", VPN: "up"}}}
	setNet := func(vpn []string) {
		stateMu.Lock()
		analysis = netAnalysis{VPN: vpn, Active: map[string]bool{}}
		stateMu.Unlock()
	}
	rm := newRelayClient("default")
	rm.cfg = cfg
	t.Cleanup(func() {
		stateMu.Lock()
		analysis = netAnalysis{}
		stateMu.Unlock()
	})

	setNet([]string{"utun4"})
	if c := rm.sharedContext(); c == nil || c.Label != "office-vpn" || !c.VPN {
		t.Fatalf("on the VPN: %+v", c)
	}
	setNet(nil)
	if c := rm.sharedContext(); c == nil || c.Label != "default" || c.VPN {
		t.Fatalf("off the VPN: %+v", c)
	}
	no := false
	cfg.ShareContext = &no
	if c := rm.sharedContext(); c != nil {
		t.Fatalf("sharing off: %+v", c)
	}
}

func TestValidateNetworkLabels(t *testing.T) {
	good, err := validateNetworkLabels([]NetworkLabel{{Label: "  office\x00 ", VPN: " UP ", IFaceUp: " utun* "}, {Label: "lan", Net: "10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if good[0].Label != "office" || good[0].VPN != "up" || good[0].IFaceUp != "utun*" {
		t.Fatalf("normalization: %+v", good[0])
	}
	for name, in := range map[string][]NetworkLabel{
		"empty label":        {{VPN: "up"}},
		"no condition":       {{Label: "x"}},
		"bad vpn":            {{Label: "x", VPN: "maybe"}},
		"bad cidr":           {{Label: "x", Net: "10.0.0.0"}},
		"bad gateway":        {{Label: "x", Gateway: "gw"}},
		"bad interface glob": {{Label: "x", IFaceUp: "[oops"}},
	} {
		if _, err := validateNetworkLabels(in); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
	many := make([]NetworkLabel, 31)
	for i := range many {
		many[i] = NetworkLabel{Label: "x", VPN: "up"}
	}
	if _, err := validateNetworkLabels(many); err == nil {
		t.Error("too many entries")
	}
}

func TestRelayConfigInfoShowsWhatIsSharedNow(t *testing.T) {
	cfg := &RelayConfig{Address: "r.example:8443", NetworkLabel: "default", NetworkLabels: []NetworkLabel{{Label: "office-vpn", VPN: "up"}}}
	configMu.Lock()
	old := configuration.Relays
	configuration.Relays = []*RelayConfig{cfg}
	configMu.Unlock()
	stateMu.Lock()
	analysis = netAnalysis{VPN: []string{"utun4"}, Active: map[string]bool{}}
	stateMu.Unlock()
	t.Cleanup(func() {
		configMu.Lock()
		configuration.Relays = old
		configMu.Unlock()
		stateMu.Lock()
		analysis = netAnalysis{}
		stateMu.Unlock()
	})
	configMu.Lock()
	info := relayConfigInfoLocked(cfg)
	configMu.Unlock()
	if !info.SharedNow.Sharing || info.SharedNow.Label != "office-vpn" || !info.SharedNow.VPN || info.SharedNow.Rule != 0 {
		t.Fatalf("shared now: %+v", info.SharedNow)
	}
	if len(info.NetworkLabels) != 1 || info.NetworkLabel != "default" {
		t.Fatalf("table: %+v", info)
	}
}
