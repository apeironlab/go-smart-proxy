package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// fakeHTTPProxy accepts CONNECT and tunnels to the requested address.
func fakeHTTPProxy(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != "CONNECT" {
					c.Close()
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					c.Close()
					return
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
				go io.Copy(up, br)
				io.Copy(c, up)
				c.Close()
				up.Close()
			}()
		}
	}()
	return l.Addr().String()
}

// fakeSocks5 is a no-auth SOCKS5 server.
func fakeSocks5(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				h := make([]byte, 2)
				io.ReadFull(c, h)
				io.CopyN(io.Discard, c, int64(h[1]))
				c.Write([]byte{5, 0})
				r := make([]byte, 4)
				io.ReadFull(c, r)
				var host string
				switch r[3] {
				case 1:
					b := make([]byte, 4)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				case 3:
					l := make([]byte, 1)
					io.ReadFull(c, l)
					b := make([]byte, l[0])
					io.ReadFull(c, b)
					host = string(b)
				}
				p := make([]byte, 2)
				io.ReadFull(c, p)
				port := int(p[0])<<8 | int(p[1])
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return l.Addr().String()
}

func TestRelayHopDevice(t *testing.T) {
	chain, err := buildChain([]ConfigHop{{ProxyUrl: "relay://alice@example.com/quiet-otter"}})
	if err != nil {
		t.Fatal(err)
	}
	if chain[0].addr != "alice@example.com" || chain[0].device != "quiet-otter" {
		t.Fatalf("unexpected relay hop: %+v", chain[0])
	}
	if got := chainStrings(chain); len(got) != 1 || got[0] != "relay://alice@example.com/quiet-otter" {
		t.Fatalf("chain string = %v", got)
	}
	if _, err := buildChain([]ConfigHop{{ProxyUrl: "relay://alice@example.com/bad/device"}}); err == nil {
		t.Fatal("a device code with a slash must be rejected")
	}
}

func TestDynamicHopWithoutRuleConnectsDirectly(t *testing.T) {
	resetEnv(t, nil, nil)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "dynamic direct")
	}))
	defer origin.Close()

	route := &ProxyRoute{name: "dyn", chain: []*chainHop{{scheme: "dynamic"}}}
	target := origin.Listener.Addr().String()
	rec := connReg.newConn("tunnel", "", "", target, "", "dyn", "", "", "")
	conn, br, err := dialChain(route, target, "unmatched.local", rec)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: unmatched.local\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "dynamic direct" {
		t.Fatalf("got %q", b)
	}
}

func TestChainHTTPThenSocks5(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello via chain")
	}))
	defer origin.Close()

	hop1 := fakeHTTPProxy(t)
	hop2 := fakeSocks5(t)
	chain, err := buildChain([]ConfigHop{{ProxyUrl: "http://" + hop1}, {ProxyUrl: "socks5://" + hop2}})
	if err != nil {
		t.Fatal(err)
	}
	route := &ProxyRoute{name: "t", chain: chain}

	// CONNECT-style tunnel
	rec := connReg.newConn("tunnel", "", "", origin.Listener.Addr().String(), "", "t", "", "", "")
	conn, br, err := dialChain(route, origin.Listener.Addr().String(), "127.0.0.1", rec)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	conn.Close()
	if string(b) != "hello via chain" {
		t.Fatalf("got %q", b)
	}

	// plain HTTP through the chain transport
	route.mu.Lock()
	tr := route.newChainTransport()
	route.mu.Unlock()
	resp, err = (&http.Client{Transport: tr}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	if string(b) != "hello via chain" {
		t.Fatalf("transport got %q", b)
	}
}
