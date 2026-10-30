package main

import (
	"net"
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
