package main

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

// socksProxy is a SOCKS5 server that tunnels to wherever it is asked.
func startSocksHop(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				head := make([]byte, 2)
				io.ReadFull(br, head)
				io.CopyN(io.Discard, br, int64(head[1]))
				c.Write([]byte{0x05, 0x00})
				req := make([]byte, 4)
				io.ReadFull(br, req)
				var host string
				switch req[3] {
				case 0x01:
					b := make([]byte, 4)
					io.ReadFull(br, b)
					host = net.IP(b).String()
				case 0x03:
					n, _ := br.ReadByte()
					b := make([]byte, n)
					io.ReadFull(br, b)
					host = string(b)
				}
				pb := make([]byte, 2)
				io.ReadFull(br, pb)
				up, err := net.Dial("tcp", net.JoinHostPort(host, itoa(int(pb[0])<<8|int(pb[1]))))
				if err != nil {
					c.Write([]byte{0x05, 0x05, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{0x05, 0x00, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, br)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestDialChainThroughSocksAndErrors(t *testing.T) {
	resetEnv(t, nil, nil)
	backend := startGreetingServer(t, "hi there\n")
	socks := startSocksHop(t)

	route, err := newProxyRoute(&ConfigRoute{Name: "viasocks", Chain: []ConfigHop{{ProxyUrl: "socks5://" + socks}}})
	if err != nil {
		t.Fatal(err)
	}
	rec := connReg.newConn("test", "", "127.0.0.1", backend, "", "viasocks", "", "", "")
	conn, br, err := dialChain(route, backend, "127.0.0.1", rec)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := br.ReadString('\n')
	conn.Close()
	if !strings.Contains(line, "hi there") {
		t.Errorf("through the SOCKS hop: %q", line)
	}
	// the hop refuses to reach the target
	rec = connReg.newConn("test", "", "127.0.0.1", "127.0.0.1:1", "", "viasocks", "", "", "")
	if _, _, err := dialChain(route, "127.0.0.1:1", "127.0.0.1", rec); err == nil || !strings.Contains(err.Error(), "hop 1") {
		t.Errorf("a refused target: %v", err)
	}
	// the first hop does not exist
	dead := &ProxyRoute{name: "dead", chain: []*chainHop{{scheme: "http", addr: "127.0.0.1:1"}, {scheme: "http", addr: "127.0.0.1:2"}}}
	if _, _, err := dialChain(dead, backend, "127.0.0.1", rec); err == nil || !strings.Contains(err.Error(), "hop 1") {
		t.Errorf("a dead first hop: %v", err)
	}
	// hops that cannot be traversed
	for name, hops := range map[string][]*chainHop{
		"pac first":   {{scheme: "pac", addr: "http://pac/p.pac"}},
		"pac later":   {{scheme: "socks5", addr: socks}, {scheme: "pac", addr: "http://pac/p.pac"}},
		"relay later": {{scheme: "socks5", addr: socks}, {scheme: "relay", addr: "a@example.org"}},
	} {
		r := &ProxyRoute{name: name, chain: hops}
		if _, _, err := dialChain(r, backend, "127.0.0.1", rec); err == nil {
			t.Errorf("%s: dialed", name)
		}
	}
	// no relay is configured: an application hop and a relay hop fail cleanly
	for _, h := range []*chainHop{{scheme: "relayapp", relayName: "none", device: "wiki"}, {scheme: "relay", addr: "a@example.org"}} {
		if _, _, err := dialChain(&ProxyRoute{name: "r", chain: []*chainHop{h}}, backend, "127.0.0.1", rec); err == nil {
			t.Errorf("%s hop dialed without a relay", h.scheme)
		}
	}
	// a dynamic hop with nothing to expand goes straight to the target
	direct := &ProxyRoute{name: "dyn", chain: []*chainHop{{scheme: "dynamic"}}}
	rec = connReg.newConn("test", "", "127.0.0.1", backend, "", "dyn", "", "", "")
	if c, br, err := dialChain(direct, backend, "127.0.0.1", rec); err != nil {
		t.Errorf("dynamic to the target: %v", err)
	} else {
		line, _ := br.ReadString('\n')
		c.Close()
		if !strings.Contains(line, "hi there") {
			t.Errorf("dynamic direct: %q", line)
		}
	}
}

func TestBuildChainDefaultsAndCredentials(t *testing.T) {
	old := configuration
	t.Cleanup(func() { configuration = old })
	configuration.Credentials = []ConfigCredential{{Name: "corp", User: "ann", Password: "pw"}}
	hops, err := buildChain([]ConfigHop{{ProxyUrl: "http://proxy.example"}, {ProxyUrl: "socks5://socks.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if hops[0].addr != "proxy.example:8080" || hops[1].addr != "socks.example:1080" {
		t.Errorf("default ports: %q %q", hops[0].addr, hops[1].addr)
	}
	hops, err = buildChain([]ConfigHop{{ProxyUrl: "http://proxy.example:3128", Credential: "corp"}})
	if err != nil || hops[0].user != "ann" || hops[0].password != "pw" {
		t.Errorf("credential: %+v %v", hops, err)
	}
	hops, err = buildChain([]ConfigHop{{ProxyUrl: "http://bob:secret@proxy.example:3128"}})
	if err != nil || hops[0].user != "bob" || hops[0].password != "secret" {
		t.Errorf("credentials in the URL: %+v %v", hops, err)
	}
	for name, h := range map[string]ConfigHop{
		"unknown credential": {ProxyUrl: "http://proxy.example:3128", Credential: "nope"},
		"unsupported scheme": {ProxyUrl: "ftp://proxy.example:21"},
	} {
		if _, err := buildChain([]ConfigHop{h}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDynamicHopsThroughAPACRoute(t *testing.T) {
	t.Chdir(t.TempDir())
	pac := &ProxyRoute{name: "pac", pacUrl: "http://pac.example/p.pac"}
	// without a loaded PAC the answer is DIRECT: nothing to add
	if got := dynamicRouteHops(pac, "example.org", "example.org:443", map[string]bool{}, 0); got != nil {
		t.Errorf("an empty PAC: %v", got)
	}
}
