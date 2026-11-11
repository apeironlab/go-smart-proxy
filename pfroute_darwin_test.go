//go:build darwin

package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPfRules(t *testing.T) {
	r := pfRules([]string{"utun5", "en0"}, "127.0.0.1:3129")
	for _, want := range []string{
		"no rdr on lo0 inet proto tcp from any to 127.0.0.0/8",
		"rdr on lo0 inet proto tcp from any to any -> 127.0.0.1 port 3129",
		"pass in quick on lo0 reply-to (lo0 127.0.0.1) inet proto tcp from any to 127.0.0.1 port 3129 keep state",
		"pass out quick on utun5 inet proto tcp from any to any tos 0x20 no state",
		"pass out quick on utun5 inet proto tcp from any to { 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4 } no state",
		"pass out on utun5 route-to (lo0 127.0.0.1) inet proto tcp from any to any keep state",
		"pass out on en0 route-to (lo0 127.0.0.1)",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("rules lack %q:\n%s", want, r)
		}
	}
	if strings.Index(r, "quick on utun5") > strings.Index(r, "pass out on utun5 route-to") {
		t.Error("the exclusions must come before route-to")
	}
	if strings.Index(r, "no rdr") > strings.Index(r, "\nrdr on lo0") {
		t.Error("no rdr must come before rdr")
	}
}

func TestParsePfStates(t *testing.T) {
	out := `No ALTQ support in kernel
ALTQ related functions disabled
ALL tcp 127.0.0.1:3129 <- 17.248.250.13:443 <- 10.13.169.227:64682       SYN_SENT:ESTABLISHED
   [1970 + 65535] wscale 6  [0 + 65535] wscale 6
   age 00:00:03, expires in 00:00:27, 5:3 pkts, 330:204 bytes
ALL tcp 127.0.0.1:3129 <- 10.1.2.3:22 <- 192.168.1.6:50000       ESTABLISHED:ESTABLISHED
ALL tcp 10.0.0.1:443 <- 10.0.0.9:50001       ESTABLISHED:ESTABLISHED
`
	m := parsePfStates(out, "127.0.0.1:3129")
	if len(m) != 2 || m["10.13.169.227:64682"] != "17.248.250.13:443" || m["192.168.1.6:50000"] != "10.1.2.3:22" {
		t.Fatalf("got %v", m)
	}
}

func TestHelperRejectsBadInterfaces(t *testing.T) {
	h := &pfHelper{}
	for _, bad := range []string{"utun5; rm -rf /", "en0 all", "", "../x", "utun"} {
		if err := h.load([]string{bad}); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestHelperProtocol(t *testing.T) {
	dir := t.TempDir()
	fake := dir + "/pfctl"
	script := `#!/bin/sh
case "$*" in
  "-E") echo "Token : 42" ;;
  "-ss") echo "ALL tcp 127.0.0.1:3129 <- 8.8.8.8:853 <- 10.0.0.2:5555       ESTABLISHED:ESTABLISHED" ;;
  *) cat >> ` + dir + `/calls.txt; echo "$*" >> ` + dir + `/args.txt ;;
esac
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := pfctlBin
	pfctlBin = fake
	defer func() { pfctlBin = old }()

	sock := dir + "/s.sock"
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h := &pfHelper{}
	quit := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			h.handle(c, uint32(os.Getuid()), quit)
		}
	}()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rd := bufio.NewReader(c)
	call := func(req string) helperResponse {
		c.Write([]byte(req + "\n"))
		line, err := rd.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var r helperResponse
		json.Unmarshal(line, &r)
		return r
	}
	if r := call(`{"op":"ping"}`); !r.OK {
		t.Fatalf("ping: %+v", r)
	}
	if r := call(`{"op":"load","ifaces":["utun5"]}`); !r.OK {
		t.Fatalf("load: %+v", r)
	}
	if h.token != "42" {
		t.Fatalf("token = %q", h.token)
	}
	if b, _ := os.ReadFile(dir + "/calls.txt"); !strings.Contains(string(b), "route-to (lo0 127.0.0.1)") {
		t.Fatalf("rules not loaded: %q", b)
	}
	if r := call(`{"op":"load","ifaces":["utun5;x"]}`); r.OK {
		t.Fatal("a bad interface must be refused")
	}
	if r := call(`{"op":"lookup","src":"10.0.0.2:5555"}`); !r.OK || r.Dst != "8.8.8.8:853" {
		t.Fatalf("lookup: %+v", r)
	}
	if r := call(`{"op":"lookup","src":"10.0.0.2:9"}`); r.OK {
		t.Fatalf("unknown connection must fail: %+v", r)
	}
	if r := call(`{"op":"nope"}`); r.OK {
		t.Fatal("unknown operation")
	}
	if r := call(`{"op":"quit"}`); !r.OK {
		t.Fatal("quit")
	}
	select {
	case <-quit:
	case <-time.After(time.Second):
		t.Fatal("quit not signalled")
	}
}
