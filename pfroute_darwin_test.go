//go:build darwin

package main

import (
	"strings"
	"testing"
)

func TestPfRules(t *testing.T) {
	r := pfRules([]string{"utun5", "en0"}, "127.0.0.1:3129")
	for _, want := range []string{
		"rdr on lo0 inet proto tcp from any to any port { 80, 443 } -> 127.0.0.1 port 3129",
		"pass in quick on lo0 reply-to (lo0 127.0.0.1) inet proto tcp from any to 127.0.0.1 port 3129 keep state",
		"pass out quick on utun5 inet proto tcp from any to any port { 80, 443 } tos 0x20 no state",
		"pass out on utun5 route-to (lo0 127.0.0.1) inet proto tcp from any to any port { 80, 443 } keep state",
		"pass out on en0 route-to (lo0 127.0.0.1)",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("rules lack %q:\n%s", want, r)
		}
	}
	if strings.Index(r, "quick on utun5") > strings.Index(r, "pass out on utun5 route-to") {
		t.Error("the exclusion of the marked traffic must come before route-to")
	}
}
