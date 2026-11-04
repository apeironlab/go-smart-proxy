package main

import (
	"testing"

	"proxy/relay"
)

// setRelayState replaces what the relay told us about contacts for a test.
func setRelayState(t *testing.T, st relay.State, device string) {
	t.Helper()
	relayMgr.mu.Lock()
	old, oldDev := relayMgr.state, relayMgr.device
	relayMgr.state, relayMgr.device = st, device
	relayMgr.mu.Unlock()
	t.Cleanup(func() {
		relayMgr.mu.Lock()
		relayMgr.state, relayMgr.device = old, oldDev
		relayMgr.mu.Unlock()
	})
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
	save := func(rc *RelayConfig, vpn []string) {
		stateMu.Lock()
		analysis = netAnalysis{VPN: vpn}
		stateMu.Unlock()
		relayMgr.mu.Lock()
		relayMgr.cfg = rc
		relayMgr.mu.Unlock()
	}
	t.Cleanup(func() {
		stateMu.Lock()
		analysis = netAnalysis{}
		stateMu.Unlock()
		relayMgr.mu.Lock()
		relayMgr.cfg = nil
		relayMgr.mu.Unlock()
	})

	save(&RelayConfig{NetworkLabel: "office-vpn"}, []string{"utun4"})
	if c := relayMgr.sharedContext(); c == nil || c.Label != "office-vpn" || !c.VPN {
		t.Fatalf("default is to share label and VPN: %+v", c)
	}
	save(&RelayConfig{NetworkLabel: "home"}, nil)
	if c := relayMgr.sharedContext(); c == nil || c.VPN {
		t.Fatalf("no VPN: %+v", c)
	}
	save(&RelayConfig{NetworkLabel: "secret", ShareContext: &no}, []string{"utun4"})
	if c := relayMgr.sharedContext(); c != nil {
		t.Fatalf("sharing off must share nothing: %+v", c)
	}
	save(&RelayConfig{ShareContext: &yes}, nil)
	if c := relayMgr.sharedContext(); c == nil || c.Label != "" {
		t.Fatalf("no label chosen: only the VPN flag goes out: %+v", c)
	}
}
