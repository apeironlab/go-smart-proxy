package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// rawProxyRequest sends one request to our proxy and returns the status line
// and the body.
func rawProxyRequest(t *testing.T, proxyAddr, request string) (string, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	io.WriteString(c, request)
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	c.SetDeadline(time.Now().Add(700 * time.Millisecond)) // the body, if the proxy closes
	body, _ := io.ReadAll(br)
	return strings.TrimSpace(status), string(body)
}

func TestProxyRefusesWhatItShould(t *testing.T) {
	old := configuration
	t.Cleanup(func() { configuration = old; loadRoutes() })
	resetEnv(t, nil, nil)
	proxy := startOurProxy(t)
	_, port, _ := net.SplitHostPort(proxy)
	configMu.Lock()
	configuration.Address = proxy // the address the proxy believes it listens on
	configMu.Unlock()

	cases := map[string]struct{ req, want string }{
		"not http":             {"GET ftp://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n", "400"},
		"itself":               {"GET http://127.0.0.1:" + port + "/ HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n", "403"},
		"connect to itself":    {"CONNECT 127.0.0.1:" + port + " HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n", "50"},
		"connect, no listener": {"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n", "50"},
	}
	for name, c := range cases {
		status, _ := rawProxyRequest(t, proxy, c.req)
		if !strings.Contains(status, c.want) {
			t.Errorf("%s: %q, want %s", name, status, c.want)
		}
	}
	// the interface itself is served to the local machine
	status, _ := rawProxyRequest(t, proxy, "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:"+port+"\r\n\r\n")
	if !strings.Contains(status, "200") && !strings.Contains(status, "401") && !strings.Contains(status, "403") {
		t.Errorf("api: %q", status)
	}
}

func TestPlainHTTPGoesDirect(t *testing.T) {
	old := configuration
	t.Cleanup(func() { configuration = old; loadRoutes() })
	resetEnv(t, nil, nil)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s %s", r.Method, r.URL.Path)
	}))
	defer backend.Close()
	proxy := startOurProxy(t)
	u := backend.URL
	status, body := rawProxyRequest(t, proxy, "GET "+u+"/page HTTP/1.1\r\nHost: "+strings.TrimPrefix(u, "http://")+"\r\nConnection: close\r\n\r\n")
	if !strings.Contains(status, "200") || !strings.Contains(body, "hello GET /page") {
		t.Errorf("direct request: %q %q", status, body)
	}
	// a POST with a body, and a destination that does not answer
	status, body = rawProxyRequest(t, proxy, "POST "+u+"/up HTTP/1.1\r\nHost: "+strings.TrimPrefix(u, "http://")+"\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
	if !strings.Contains(status, "200") || !strings.Contains(body, "hello POST /up") {
		t.Errorf("post: %q %q", status, body)
	}
	status, _ = rawProxyRequest(t, proxy, "GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n")
	if !strings.Contains(status, "502") && !strings.Contains(status, "503") {
		t.Errorf("an unreachable destination: %q", status)
	}
}

func TestHTTPConnectThroughAnUpstreamThatRefuses(t *testing.T) {
	refuser, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer refuser.Close()
	go func() {
		for {
			c, err := refuser.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
				}
				io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			}()
		}
	}()
	up, _ := net.Dial("tcp", refuser.Addr().String())
	defer up.Close()
	err = httpConnect(up, bufio.NewReader(up), "", "", "example.org:443", nil)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("a refusing upstream: %v", err)
	}
	// and a closed connection
	a, b := net.Pipe()
	b.Close()
	if err := httpConnect(a, bufio.NewReader(a), "u", "p", "example.org:443", &ConnInfo{}); err == nil {
		t.Error("a closed upstream went unnoticed")
	}
}

func TestResolveHostCachesAndHonoursLiterals(t *testing.T) {
	resetEnv(t, nil, nil)
	if got := resolveHost("127.0.0.1"); got != "127.0.0.1" {
		t.Errorf("literal = %q", got)
	}
	if got := resolveHost("localhost"); got == "" {
		t.Error("localhost did not resolve")
	}
	first := resolveHost("localhost")
	if second := resolveHost("localhost"); second != first {
		t.Errorf("cache: %q then %q", first, second)
	}
	if got := resolveHost("no-such-host.invalid"); got != "" {
		t.Errorf("an unknown name resolved to %q", got)
	}
}

func TestServeAndRestartListener(t *testing.T) {
	old := configuration
	t.Cleanup(func() { configuration = old })
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	configMu.Lock()
	configuration.Address = addr
	configMu.Unlock()
	serveStopped.Store(false)
	t.Cleanup(func() {
		serveStopped.Store(true)
		restartListener()
		time.Sleep(100 * time.Millisecond)
	})
	go serve()
	var c net.Conn
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		var err error
		if c, err = net.DialTimeout("tcp", addr, time.Second); err == nil {
			break
		}
	}
	if c == nil {
		t.Fatal("the proxy listener did not start")
	}
	c.Close()
	restartListener() // the loop opens it again
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if c2, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c2.Close()
			return
		}
	}
	t.Error("the listener was not reopened")
}
