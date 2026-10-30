package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/expirablelru"
)

func type2Message() string {
	msg := make([]byte, 48)
	copy(msg[0:], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:], 2)           // message type
	binary.LittleEndian.PutUint32(msg[20:], 0x00000201) // flags: UNICODE | NTLM
	copy(msg[24:], []byte{1, 2, 3, 4, 5, 6, 7, 8})      // server challenge
	return base64.StdEncoding.EncodeToString(msg)
}

// Real proxies (Squid) answer 407 with an HTML error page body, which must
// not break the handshake.
const fake407Body = "<!DOCTYPE html><html><body><h1>Proxy Authentication Required</h1><p>Cache Access Denied.</p></body></html>"

func resetEnv(t *testing.T, creds []ConfigCredential, routes []ConfigRoute) {
	t.Helper()
	dnsCache = expirablelru.NewExpirableLRU(500, nil, time.Hour, time.Hour)
	configuration = Configuration{Credentials: creds, Routes: routes}
	loadRoutes()
}

func startOurProxy(t *testing.T) string {
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
			go func(conn net.Conn) {
				server := &http.Server{
					Handler:           http.HandlerFunc(proxyHandler),
					ReadHeaderTimeout: 30 * time.Second,
					IdleTimeout:       2 * time.Minute,
				}
				server.Serve(&singleConnListener{conn: conn})
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startFakeNTLMProxy behaves like a corporate NTLM proxy: it answers 407
// challenges until the client completes the Type3 message, then either
// responds as the origin (plain HTTP) or tunnels the connection to backendAddr
// (CONNECT). The authentication is connection-based, like Squid. Requests are
// parsed manually so that the raw request line and Host header are visible.
func startFakeNTLMProxy(t *testing.T, backendAddr string) (string, <-chan string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	connectTargets := make(chan string, 16)
	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				authenticated := false
				for {
					firstLine, headers, body, ok := readRawRequest(br)
					if !ok {
						return
					}
					pa := headers["Proxy-Authorization"]
					if !authenticated {
						if strings.HasPrefix(pa, "NTLM TlRMTVNTUAAD") {
							authenticated = true
						} else {
							fmt.Fprintf(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s",
								type2Message(), len(fake407Body), fake407Body)
							continue
						}
					}
					_, target, _ := strings.Cut(firstLine, " ")
					target, _, _ = strings.Cut(target, " ")
					if strings.HasPrefix(firstLine, "CONNECT ") {
						connectTargets <- target
						fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
						if backendAddr == "" {
							return
						}
						back, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
						if err != nil {
							return
						}
						defer back.Close()
						go func() {
							io.Copy(back, br)
							if cw, ok := back.(*net.TCPConn); ok {
								cw.CloseWrite()
							}
						}()
						io.Copy(c, back)
						return
					}
					payload := firstLine + "|" + headers["Host"] + "|" + string(body)
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)
				}
			}(c)
		}
	}()
	return ln.Addr().String(), connectTargets, &conns
}

func readRawRequest(br *bufio.Reader) (firstLine string, headers map[string]string, body []byte, ok bool) {
	headers = make(map[string]string)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", nil, nil, false
	}
	firstLine = strings.TrimRight(line, "\r\n")
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return "", nil, nil, false
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		k, v, _ := strings.Cut(h, ":")
		headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if cl, err := strconv.Atoi(headers["Content-Length"]); err == nil && cl > 0 {
		body = make([]byte, cl)
		if _, err := io.ReadFull(br, body); err != nil {
			return "", nil, nil, false
		}
	}
	return firstLine, headers, body, true
}

func startGreetingServer(t *testing.T, greeting string) string {
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
			go func(c net.Conn) {
				defer c.Close()
				io.WriteString(c, greeting)
				time.Sleep(200 * time.Millisecond)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestPlainHTTPThroughNTLMProxy(t *testing.T) {
	fake, _, _ := startFakeNTLMProxy(t, "")
	resetEnv(t,
		[]ConfigCredential{{Name: "test", User: "DOMAIN\\user", Password: "pass"}},
		[]ConfigRoute{{Name: "proxy", ProxyUrl: "http://" + fake, Credential: "test"}},
	)
	ourProxy := startOurProxy(t)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: ourProxy}),
		},
		Timeout: 20 * time.Second,
	}

	// POST with query and body: everything must survive the trip.
	resp, err := client.Post("http://localhost:54321/echo?q=1&x=2", "text/plain", strings.NewReader("REQUEST-BODY"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(data), "|", 3)
	if len(parts) != 3 {
		t.Fatalf("unexpected echo payload: %q", data)
	}
	if parts[0] != "POST http://localhost:54321/echo?q=1&x=2 HTTP/1.1" {
		t.Errorf("upstream saw wrong request line: %q", parts[0])
	}
	if parts[1] != "localhost:54321" {
		t.Errorf("Host header not preserved: %q", parts[1])
	}
	if parts[2] != "REQUEST-BODY" {
		t.Errorf("body corrupted: %q", parts[2])
	}

	// Second request reuses the authenticated connection (keep-alive).
	resp, err = client.Get("http://localhost:54321/second")
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(data), "GET http://localhost:54321/second HTTP/1.1|localhost:54321|") {
		t.Errorf("keep-alive request failed: %q", data)
	}
}

func TestConnectThroughNTLMProxy(t *testing.T) {
	backend := startGreetingServer(t, "HELLO-TUNNEL")
	fake, connectTargets, _ := startFakeNTLMProxy(t, backend)
	resetEnv(t,
		[]ConfigCredential{{Name: "test", User: "DOMAIN\\user", Password: "pass"}},
		[]ConfigRoute{{Name: "proxy", ProxyUrl: "http://" + fake, Credential: "test"}},
	)
	ourProxy := startOurProxy(t)

	// CONNECT using the hostname: the proxy must resolve it locally and send
	// the IP address upstream (privacy), not the hostname.
	host, port, _ := net.SplitHostPort(backend)
	conn, err := net.DialTimeout("tcp", ourProxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", port, port)

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected CONNECT status %d", resp.StatusCode)
	}

	select {
	case target := <-connectTargets:
		if target != net.JoinHostPort(host, port) {
			t.Fatalf("proxy saw hostname upstream, expected IP: %q", target)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake proxy never saw the CONNECT target")
	}

	buf := make([]byte, len("HELLO-TUNNEL"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("early tunnel bytes lost: %v", err)
	}
	if string(buf) != "HELLO-TUNNEL" {
		t.Fatalf("unexpected greeting %q", buf)
	}
}

func TestConnectDirect(t *testing.T) {
	backend := startGreetingServer(t, "DIRECT-GREETING")
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	ourProxy := startOurProxy(t)

	host, port, _ := net.SplitHostPort(backend)
	conn, err := net.DialTimeout("tcp", ourProxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected CONNECT status %d", resp.StatusCode)
	}

	buf := make([]byte, len("DIRECT-GREETING"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("direct tunnel bytes lost: %v", err)
	}
	if string(buf) != "DIRECT-GREETING" {
		t.Fatalf("unexpected greeting %q", buf)
	}
}

func TestPacRouteSelectionAndFallback(t *testing.T) {
	pacSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `function FindProxyForURL(url, host) { return "PROXY 10.99.0.1:8080"; }`)
	}))

	resetEnv(t, nil, []ConfigRoute{{Name: "pac", PacUrl: pacSrv.URL}})

	// The PAC is fetched asynchronously: poll until the route becomes usable.
	var route *ProxyRoute
	deadline := time.Now().Add(10 * time.Second)
	for {
		route = GetApplicableRoute()
		if route != nil && route.name == "pac" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("PAC route never became applicable")
		}
		time.Sleep(20 * time.Millisecond)
	}

	proxy := route.FindProxy("http://example.com/")
	if proxy.Type != "PROXY" || proxy.Address != "10.99.0.1:8080" {
		t.Fatalf("unexpected proxy: %+v", proxy)
	}

	cacheFile := route.pacCacheFile()
	defer os.Remove(cacheFile)

	// PAC server goes away: the cached copy must keep the route working.
	pacSrv.Close()
	route.invalidatePAC()
	if err := route.Check(); err != nil {
		t.Fatalf("Check failed with PAC server down: %v", err)
	}
	proxy = route.FindProxy("http://example.com/")
	if proxy.Type != "PROXY" || proxy.Address != "10.99.0.1:8080" {
		t.Fatalf("fallback proxy wrong: %+v", proxy)
	}
}

func TestRouteFilteringSkipsPAC(t *testing.T) {
	var hits atomic.Int32
	pacSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `function FindProxyForURL(url, host) { return "PROXY 10.99.0.1:8080"; }`)
	}))

	// The route's interface does not match: its PAC must never be fetched.
	resetEnv(t, nil, []ConfigRoute{
		{Name: "office", IFace: "definitely-not-an-interface", PacUrl: pacSrv.URL},
	})

	route := GetApplicableRoute()
	if route == nil || route.name != "Direct" {
		t.Fatalf("expected Direct route, got %+v", route)
	}
	time.Sleep(300 * time.Millisecond)
	if got := hits.Load(); got != 0 {
		t.Fatalf("PAC fetched for non-matching route (%d hits)", got)
	}
}

func TestConnectionResetClosesActiveConnections(t *testing.T) {
	backend := startGreetingServer(t, "HELLO")
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	ourProxy := startOurProxy(t)

	host, port, _ := net.SplitHostPort(backend)
	conn, err := net.DialTimeout("tcp", ourProxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected CONNECT status %d", resp.StatusCode)
	}
	buf := make([]byte, len("HELLO"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("greeting not received: %v", err)
	}

	// Simulate a network change: all connections must be closed.
	resetConnections()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("client connection still open after connection reset")
	}
}

func TestResetTransportsDropsPooledConnections(t *testing.T) {
	fake, _, conns := startFakeNTLMProxy(t, "")
	resetEnv(t,
		[]ConfigCredential{{Name: "test", User: "DOMAIN\\user", Password: "pass"}},
		[]ConfigRoute{{Name: "proxy", ProxyUrl: "http://" + fake, Credential: "test"}},
	)
	ourProxy := startOurProxy(t)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: ourProxy}),
		},
		Timeout: 20 * time.Second,
	}

	if _, err := client.Get("http://localhost:54321/first"); err != nil {
		t.Fatal(err)
	}
	if got := conns.Load(); got != 1 {
		t.Fatalf("expected 1 connection to fake proxy, got %d", got)
	}

	// Simulate a network change: the pooled connection must be dropped and
	// the next request must dial again.
	routes := getRoutes()
	if len(routes) == 0 {
		t.Fatal("no routes")
	}
	routes[0].resetTransports()

	if _, err := client.Get("http://localhost:54321/second"); err != nil {
		t.Fatal(err)
	}
	if got := conns.Load(); got != 2 {
		t.Fatalf("expected a fresh connection after reset, got %d total", got)
	}
}

func TestAPIAndUI(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	ourProxy := startOurProxy(t)

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get("http://" + ourProxy + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(data), `"routes"`) {
		t.Fatalf("unexpected state response: %d %s", resp.StatusCode, data)
	}

	resp, err = client.Get("http://" + ourProxy + "/")
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(data), "<div id=\"root\">") {
		t.Fatalf("UI not served: %d", resp.StatusCode)
	}
}

func TestConnectionsAPI(t *testing.T) {
	backend := startGreetingServer(t, "HELLO")
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	ourProxy := startOurProxy(t)

	host, port, _ := net.SplitHostPort(backend)
	conn, err := net.DialTimeout("tcp", ourProxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected CONNECT status %d", resp.StatusCode)
	}
	buf := make([]byte, len("HELLO"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	aresp, err := client.Get("http://" + ourProxy + "/api/connections?closed=1")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(aresp.Body)
	aresp.Body.Close()

	var snaps []connSnapshot
	if err := json.Unmarshal(data, &snaps); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, data)
	}
	found := false
	for _, s := range snaps {
		if s.Type == "tunnel" && s.Target == backend {
			found = true
			if s.State != StateClosed && s.State != StateEstablished {
				t.Errorf("unexpected tunnel state %q", s.State)
			}
			if len(s.Events) == 0 {
				t.Errorf("no events recorded for tunnel")
			}
		}
	}
	if !found {
		t.Fatalf("tunnel record not found in %+v", snaps)
	}
}

func TestCloseConnectionAPI(t *testing.T) {
	backend := startHoldingServer(t)
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	ourProxy := startOurProxy(t)

	host, port, _ := net.SplitHostPort(backend)
	conn, err := net.DialTimeout("tcp", ourProxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	if resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"}); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	aresp, err := client.Get("http://" + ourProxy + "/api/connections")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(aresp.Body)
	aresp.Body.Close()
	var snaps []connSnapshot
	if err := json.Unmarshal(data, &snaps); err != nil {
		t.Fatal(err)
	}
	var id uint64
	for _, s := range snaps {
		if s.Type == "tunnel" && s.Target == backend {
			id = s.ID
		}
	}
	if id == 0 {
		t.Fatal("tunnel record not found")
	}

	body := strings.NewReader(`{}`)
	if _, err := client.Post(fmt.Sprintf("http://%s/api/connections/%d/close", ourProxy, id), "application/json", body); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection still open after API close")
	}
}

func TestPacHandler(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	req := httptest.NewRequest("GET", "http://wpad/wpad.dat", nil)
	w := httptest.NewRecorder()
	pacHandler(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "PROXY 127.0.0.1:3128") {
		t.Fatalf("unexpected PAC content: %s", body)
	}
	if !strings.Contains(body, `host == "127.0.0.1"`) {
		t.Fatalf("PAC must bypass local hosts: %s", body)
	}
}

func startHoldingServer(t *testing.T) string {
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
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestHostsOverrideBypassesDNS(t *testing.T) {
	dnsCache = expirablelru.NewExpirableLRU(500, nil, time.Hour, time.Hour)
	configuration = Configuration{Hosts: map[string]string{"repo.intra.example.test": "192.168.8.40"}}
	defer func() { configuration = Configuration{} }()

	if got := resolveHost("repo.intra.example.test"); got != "192.168.8.40" {
		t.Fatalf("a configured host must resolve to its configured address, got %q", got)
	}
	if got := resolveHost("10.1.2.3"); got != "10.1.2.3" {
		t.Fatalf("an IP address must stay as it is, got %q", got)
	}
}
