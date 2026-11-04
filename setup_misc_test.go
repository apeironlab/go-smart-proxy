package main

import (
	"net"
	"strings"
	"testing"
)

func TestSetupHelpers(t *testing.T) {
	ln, addr, err := listenSetup()
	if err != nil {
		t.Skipf("no free port: %v", err)
	}
	defer ln.Close()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("setup page on %s", addr)
	}
	// with that port taken, the next one is used
	ln2, addr2, err := listenSetup()
	if err == nil {
		defer ln2.Close()
		if addr2 == addr {
			t.Error("the same port twice")
		}
	}
	socks := pickSocksAddress()
	if h, _, err := net.SplitHostPort(socks); err != nil || h != "127.0.0.1" {
		t.Errorf("pickSocksAddress = %q", socks)
	}
	a, b := setupToken(), setupToken()
	if len(a) < 24 || a == b {
		t.Errorf("tokens %q %q", a, b)
	}
}
