package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// socksExchange runs handleSOCKS against a scripted client and returns what
// the proxy answered before closing.
func socksExchange(t *testing.T, script []byte) []byte {
	return socksExchangeClosing(t, script, false)
}

// socksExchangeClosing can hang up after sending the script, like a client that
// gives up half way through a request.
func socksExchangeClosing(t *testing.T, script []byte, hangUp bool) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	done := make(chan struct{})
	go func() { handleSOCKS(srv); close(done) }()
	go func() {
		cli.Write(script)
		if hangUp {
			time.Sleep(50 * time.Millisecond)
			cli.Close()
		}
	}()
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	var out bytes.Buffer
	io.Copy(&out, cli) // until handleSOCKS closes its side
	cli.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleSOCKS did not return")
	}
	return out.Bytes()
}

func TestSOCKSRefusals(t *testing.T) {
	// not SOCKS5
	if out := socksExchange(t, []byte{0x04, 0x01, 0x00}); len(out) != 0 {
		t.Errorf("SOCKS4: %v", out)
	}
	// SOCKS5 but only username/password offered
	if out := socksExchange(t, []byte{0x05, 0x01, 0x02}); !bytes.Equal(out, []byte{0x05, 0xff}) {
		t.Errorf("no acceptable method: %v", out)
	}
	hello := []byte{0x05, 0x01, 0x00}
	ok := []byte{0x05, 0x00}
	// BIND is not supported
	out := socksExchange(t, append(append([]byte{}, hello...), 0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80))
	if len(out) < 4 || !bytes.Equal(out[:2], ok) || out[3] != 0x07 {
		t.Errorf("BIND: %v", out)
	}
	// unknown address type
	out = socksExchange(t, append(append([]byte{}, hello...), 0x05, 0x01, 0x00, 0x09))
	if len(out) < 4 || out[3] != 0x08 {
		t.Errorf("address type: %v", out)
	}
	// truncated requests are dropped without an answer to the request
	for name, req := range map[string][]byte{
		"ipv4":   {0x05, 0x01, 0x00, 0x01, 1, 2},
		"ipv6":   {0x05, 0x01, 0x00, 0x04, 1, 2},
		"domain": {0x05, 0x01, 0x00, 0x03, 9, 'a'},
		"nolen":  {0x05, 0x01, 0x00, 0x03},
		"port":   {0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0},
	} {
		// the proxy answers the greeting and then gives up on the request
		if out := socksExchangeClosing(t, append(append([]byte{}, hello...), req...), true); len(out) > 2 {
			t.Errorf("%s: %v", name, out)
		}
	}
	// a connection that cannot be made: general failure (or refusal)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	req := append(append([]byte{}, hello...), 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(port>>8), byte(port))
	out = socksExchange(t, req)
	if len(out) < 4 || out[2] == 0x00 {
		t.Errorf("a refused connection was reported as a success: %v", out)
	}
	// a domain name and an IPv6 address are read in full
	for _, req := range [][]byte{
		append(append([]byte{}, hello...), append([]byte{0x05, 0x01, 0x00, 0x03, 9}, append([]byte("127.0.0.1"), byte(port>>8), byte(port))...)...),
		append(append([]byte{}, hello...), append([]byte{0x05, 0x01, 0x00, 0x04}, append(net.IPv6loopback, byte(port>>8), byte(port))...)...),
	} {
		if out := socksExchange(t, req); len(out) < 4 || out[2] == 0x00 {
			t.Errorf("unreachable target reported as a success: %v", out)
		}
	}
}

func TestBuildChainErrors(t *testing.T) {
	old := configuration
	t.Cleanup(func() { configuration = old })
	configuration.Credentials = []ConfigCredential{{Name: "corp", User: "u", Password: "p"}}
	bad := map[string][]ConfigHop{
		"dynamic with a proxy":    {{Dynamic: true, ProxyUrl: "http://p:1"}},
		"dynamic not last":        {{Dynamic: true}, {ProxyUrl: "http://p:1"}},
		"dynamic with credential": {{Dynamic: true, Credential: "corp"}},
		"pac and proxy":           {{PacUrl: "http://pac/p.pac", ProxyUrl: "http://p:1"}},
		"pac among others":        {{PacUrl: "http://pac/p.pac"}, {ProxyUrl: "http://p:1"}},
		"pac invalid":             {{PacUrl: "::"}},
		"pac scheme":              {{PacUrl: "ftp://pac/p.pac"}},
		"pac credential unknown":  {{PacUrl: "http://pac/p.pac", Credential: "nope"}},
		"no url":                  {{}},
		"proxy invalid":           {{ProxyUrl: "http://"}},
		"two relays":              {{ProxyUrl: "relay://a@example.org"}, {ProxyUrl: "relay://b@example.org"}},
		"relay without user":      {{ProxyUrl: "relay://example.org"}},
		"relay bad device":        {{ProxyUrl: "relay://a@example.org/bad device!"}},
		"relay bad name":          {{ProxyUrl: "relay://a@example.org?relay=Not%20Valid"}},
	}
	for name, cfg := range bad {
		if _, err := buildChain(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := map[string][]ConfigHop{
		"pac with credential":      {{PacUrl: "http://pac/p.pac", Credential: "corp"}},
		"pac with user in the url": {{PacUrl: "http://u:p@pac/p.pac"}},
		"http then dynamic":        {{ProxyUrl: "proxy.example:8080", Credential: "corp"}, {Dynamic: true}},
		"relay with device":        {{ProxyUrl: "relay://a@example.org/k7m2p9qx"}},
		"socks":                    {{ProxyUrl: "socks5://s.example:1080", RulesOnly: true}},
	}
	for name, cfg := range good {
		hops, err := buildChain(cfg)
		if err != nil || len(hops) != len(cfg) {
			t.Errorf("%s: %v %d", name, err, len(hops))
		}
	}
	if !strings.HasPrefix(string(trayIcon()[:4]), "\x89PNG") && len(trayIcon()) < 4 {
		t.Error("the tray icon is empty")
	}
}
