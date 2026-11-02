package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoutingRules(t *testing.T) {
	rules, err := compileRules([]ConfigRule{
		{Name: "corp", Domains: []string{"*.Corp.Local"}, Route: "A"},
		{Name: "exact", Hosts: []string{"Host.Example.com."}, Route: "B"},
		{Name: "lan", Networks: []string{"10.0.0.0/8", "192.168.1.5"}, Route: "C"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host, rule string
	}{
		{"corp.local", "corp"},
		{"a.b.corp.local", "corp"},
		{"notcorp.local", ""},
		{"host.example.com", "exact"},
		{"x.host.example.com", ""},
		{"10.20.30.40", "lan"},
		{"192.168.1.5", "lan"},
		{"192.168.1.6", ""},
	}
	for _, c := range cases {
		got := ""
		for _, r := range rules {
			host := normHost(c.host)
			if r.matches(host, func() net.IP { return net.ParseIP(host) }) {
				got = r.name
				break
			}
		}
		if got != c.rule {
			t.Errorf("%s: got rule %q, want %q", c.host, got, c.rule)
		}
	}
	if _, err := compileRules([]ConfigRule{{Name: "bad", Networks: []string{"10.0.0/8"}, Route: "A"}}); err == nil {
		t.Error("invalid CIDR must be rejected")
	}
	if _, err := compileRules([]ConfigRule{{Name: "empty", Route: "A"}}); err == nil {
		t.Error("a rule without matchers must be rejected")
	}
}

func TestRulesOnlyRoutes(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{
		{Name: "relay", RulesOnly: true, Chain: []ConfigHop{{ProxyUrl: "http://127.0.0.1:1"}}},
	})
	t.Cleanup(func() { setForceRoute(nil) })

	// Never selected as the automatic route.
	if r := GetApplicableRoute(); r == nil || r.name != "Direct" {
		t.Fatalf("default route = %v, want Direct", r)
	}

	// But a destination rule can still select it.
	configuration.Rules = []ConfigRule{{Name: "corp", Domains: []string{"corp.local"}, Route: "relay"}}
	loadRoutes()
	if r, rule := routeFor("corp.local"); r == nil || r.name != "relay" || rule != "corp" {
		t.Fatalf("route for corp.local = %v (%q), want relay (corp)", r, rule)
	}
	if r, rule := routeFor("example.com"); r == nil || r.name != "Direct" || rule != "" {
		t.Fatalf("route for example.com = %v (%q), want Direct", r, rule)
	}
}

func TestRulesAPIEmitsEmptyArrays(t *testing.T) {
	configuration = Configuration{Rules: []ConfigRule{
		{Name: "corp", Domains: []string{"corp.local"}, Route: "Direct"},
	}}
	t.Cleanup(func() { configuration = Configuration{} })

	m := http.NewServeMux()
	registerRuleRoutes(m)
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/rules", nil))

	var rules []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	// The web UI uses .length on these fields: null would crash the page.
	for _, field := range []string{"domains", "hosts", "networks"} {
		if _, ok := rules[0][field].([]any); !ok {
			t.Errorf("%s is %v, want an array", field, rules[0][field])
		}
	}
}
