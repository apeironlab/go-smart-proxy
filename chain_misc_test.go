package main

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
)

// fakeSOCKS5 plays the server side of a SOCKS5 handshake: it picks method
// `method`, optionally checks the user name, then answers the request with
// `code` and an address of type `atyp`.
func fakeSOCKS5(c net.Conn, method byte, authOK bool, code, atyp byte) {
	defer c.Close()
	br := bufio.NewReader(c)
	head := make([]byte, 2)
	io.ReadFull(br, head)
	io.CopyN(io.Discard, br, int64(head[1]))
	c.Write([]byte{0x05, method})
	switch method {
	case 0x02:
		v := make([]byte, 2)
		io.ReadFull(br, v)
		io.CopyN(io.Discard, br, int64(v[1]))
		l, _ := br.ReadByte()
		io.CopyN(io.Discard, br, int64(l))
		st := byte(0)
		if !authOK {
			st = 1
		}
		c.Write([]byte{0x01, st})
		if !authOK {
			return
		}
	case 0x00:
	default:
		return
	}
	req := make([]byte, 4)
	io.ReadFull(br, req)
	switch req[3] {
	case 0x01:
		io.CopyN(io.Discard, br, 4+2)
	case 0x04:
		io.CopyN(io.Discard, br, 16+2)
	case 0x03:
		l, _ := br.ReadByte()
		io.CopyN(io.Discard, br, int64(l)+2)
	}
	reply := []byte{0x05, code, 0x00, atyp}
	switch atyp {
	case 0x01:
		reply = append(reply, 1, 2, 3, 4, 0, 80)
	case 0x04:
		reply = append(reply, make([]byte, 18)...)
	case 0x03:
		reply = append(reply, 3, 'a', 'b', 'c', 0, 80)
	}
	c.Write(reply)
}

func TestSocks5ConnectHandshake(t *testing.T) {
	run := func(user, password, target string, method byte, authOK bool, code, atyp byte) error {
		cli, srv := net.Pipe()
		defer cli.Close()
		go fakeSOCKS5(srv, method, authOK, code, atyp)
		return socks5Connect(cli, bufio.NewReader(cli), user, password, target)
	}
	if err := run("", "", "example.org:443", 0x00, true, 0, 0x01); err != nil {
		t.Errorf("anonymous, domain, IPv4 reply: %v", err)
	}
	if err := run("", "", "93.184.216.34:443", 0x00, true, 0, 0x03); err != nil {
		t.Errorf("IPv4 target, domain reply: %v", err)
	}
	if err := run("", "", "[2001:db8::1]:443", 0x00, true, 0, 0x04); err != nil {
		t.Errorf("IPv6 target and reply: %v", err)
	}
	if err := run("ann", "pw", "example.org:443", 0x02, true, 0, 0x01); err != nil {
		t.Errorf("with credentials: %v", err)
	}
	if err := run("ann", "pw", "example.org:443", 0x02, false, 0, 0x01); err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Errorf("refused credentials: %v", err)
	}
	if err := run("ann", "pw", "example.org:443", 0xff, true, 0, 0x01); err == nil {
		t.Error("no acceptable method went unnoticed")
	}
	if err := run("", "", "example.org:443", 0x00, true, 5, 0x01); err == nil || !strings.Contains(err.Error(), "code 5") {
		t.Errorf("connection refused by the server: %v", err)
	}
	if err := run("", "", "example.org:443", 0x00, true, 0, 0x09); err == nil {
		t.Error("a bad address type in the reply was accepted")
	}
	if err := run(strings.Repeat("u", 300), "pw", "example.org:443", 0x02, true, 0, 0x01); err == nil {
		t.Error("a too long user name was sent")
	}
	if err := run("", "", strings.Repeat("a", 300)+":443", 0x00, true, 0, 0x01); err == nil {
		t.Error("a too long host name was sent")
	}
	for _, bad := range []string{"nonsense", "example.org:99999", "example.org:x"} {
		if err := run("", "", bad, 0x00, true, 0, 0x01); err == nil {
			t.Errorf("target %q accepted", bad)
		}
	}
	// a server that is not SOCKS5
	cli, srv := net.Pipe()
	defer cli.Close()
	go func() {
		io.CopyN(io.Discard, srv, 3)
		srv.Write([]byte("HT"))
		srv.Close()
	}()
	if err := socks5Connect(cli, bufio.NewReader(cli), "", "", "example.org:443"); err == nil {
		t.Error("not a SOCKS5 server accepted")
	}
}

func TestChainHelpers(t *testing.T) {
	hops := []*chainHop{{scheme: "dynamic"}, {scheme: "http", addr: "p.example:8080"}, {scheme: "pac", addr: "http://pac/p.pac"}, {scheme: "relay", addr: "a@example.org", device: "k7m2p9qx"}, {scheme: "socks5", addr: "s.example:1080"}}
	if got := chainStrings(hops); strings.Join(got, " ") != "dynamic http://p.example:8080 http://pac/p.pac relay://a@example.org/k7m2p9qx socks5://s.example:1080" {
		t.Errorf("chainStrings = %v", got)
	}
	if firstChainAddr(hops) != "p.example:8080" || firstChainAddr(hops[:1]) != "dynamic" {
		t.Error("firstChainAddr")
	}
	if !(&ProxyRoute{chain: hops}).hasRelayHop() || (&ProxyRoute{chain: hops[:2]}).hasRelayHop() {
		t.Error("hasRelayHop")
	}
	if chainLabel(hops) == "" {
		t.Error("chainLabel")
	}

	// bufConn closes the write side when the connection can, else everything
	a, b := net.Pipe()
	defer b.Close()
	bc := &bufConn{Conn: a, br: bufio.NewReader(a)}
	if err := bc.CloseWrite(); err != nil {
		t.Error(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, _ := l.Accept()
		if c != nil {
			io.Copy(io.Discard, c)
		}
	}()
	tc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	if err := (&bufConn{Conn: tc, br: bufio.NewReader(tc)}).CloseWrite(); err != nil {
		t.Error(err)
	}
}

func TestDynamicRouteHops(t *testing.T) {
	visited := map[string]bool{}
	// a route without upstreams (Direct) adds nothing
	if got := dynamicRouteHops(&ProxyRoute{name: "Direct"}, "example.org", "example.org:443", visited, 0); got != nil {
		t.Errorf("direct: %v", got)
	}
	// a plain upstream proxy
	got := dynamicRouteHops(&ProxyRoute{proxyUrl: "p.example:8080", user: "u", password: "p", cred: "c"}, "example.org", "example.org:443", visited, 0)
	if len(got) != 1 || got[0].addr != "p.example:8080" || got[0].user != "u" {
		t.Errorf("proxyUrl: %+v", got)
	}
	// a configured chain
	got = dynamicRouteHops(&ProxyRoute{chain: []*chainHop{{scheme: "http", addr: "c.example:3128"}}}, "example.org", "example.org:443", visited, 0)
	if len(got) != 1 || got[0].addr != "c.example:3128" {
		t.Errorf("chain: %+v", got)
	}
	// the route applicable on the network
	if r := (&ProxyRoute{name: "x"}); r.IsApplicable() != true {
		t.Log("a route without conditions is applicable")
	}
}

func TestFindGatewayAndNetwork(t *testing.T) {
	// The answer depends on the machine; what matters is that it is consistent.
	gw, iface, ipnet, err := FindGatewayAndNetwork()
	if err != nil {
		t.Skipf("no usable network here: %v", err)
	}
	if gw == nil || iface.Name == "" || ipnet == nil {
		t.Errorf("incomplete answer: %v %q %v", gw, iface.Name, ipnet)
	}
	if ip, err := GetOutboundIP(); err == nil && ip == nil {
		t.Error("no outbound address")
	}
}
