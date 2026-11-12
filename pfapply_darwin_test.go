//go:build darwin

package main

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeHelper runs the helper in this process, on a temporary socket, with a
// pfctl that records what it is asked and answers `-ss` with one state.
func fakeHelper(t *testing.T) (dir string, stop func()) {
	t.Helper()
	// unix socket paths are limited to about 100 bytes: keep the directory short
	d, err := os.MkdirTemp("/tmp", "pfh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	dir = d
	script := `#!/bin/sh
case "$*" in
  "-E") echo "Token : 7" ;;
  "-X 7") echo released >> ` + dir + `/calls.txt ;;
  "-ss") echo "ALL tcp 127.0.0.1:3129 <- 8.8.8.8:853 <- 10.0.0.2:5555       ESTABLISHED:ESTABLISHED" ;;
  *) echo "$*" >> ` + dir + `/calls.txt; cat >> ` + dir + `/rules.txt ;;
esac
`
	fake := dir + "/pfctl"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldBin, oldSock := pfctlBin, pfSocketFn
	pfctlBin = fake
	sock := dir + "/s.sock"
	pfSocketFn = func() string { return sock }
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	h := &pfHelper{}
	quit := make(chan struct{}, 1)
	go func() {
		<-quit
		ln.Close()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.handle(c, uint32(os.Getuid()), quit)
		}
	}()
	resetPfState()
	return dir, func() {
		ln.Close()
		select {
		case quit <- struct{}{}:
		default:
		}
		resetPfState()
		pfctlBin, pfSocketFn = oldBin, oldSock
	}
}

func resetPfState() {
	helperMu.Lock()
	if helperConn != nil {
		helperConn.Close()
		helperConn, helperRd = nil, nil
	}
	helperMu.Unlock()
	pfMu.Lock()
	pfApplied, pfStatus, pfLogged = "", transparentStatusJSON{}, ""
	pfMu.Unlock()
}

func fakeServices(t *testing.T, svcs ...activeService) {
	t.Helper()
	old := listActiveServices
	listActiveServices = func() []activeService { return svcs }
	t.Cleanup(func() { listActiveServices = old })
}

func TestApplyTransparentRoutingLoadsAndRemovesTheRules(t *testing.T) {
	apiFixture(t)
	dir, stop := fakeHelper(t)
	defer stop()
	fakeServices(t,
		activeService{ID: "net.example.vpn", Name: "Example VPN", Iface: "utun9", Dynamic: true},
		activeService{ID: "wifi", Name: "Wi-Fi", Iface: "en0"})

	configuration.TransparentRoute = []string{"example"}
	applyTransparentRouting()
	st := transparentStatus()
	if !st.Loaded || st.NeedsAuth || len(st.Interfaces) != 1 || st.Interfaces[0] != "utun9" {
		t.Fatalf("status after loading: %+v", st)
	}
	rules, _ := os.ReadFile(dir + "/rules.txt")
	if !strings.Contains(string(rules), "pass out on utun9 route-to") || strings.Contains(string(rules), "en0") {
		t.Fatalf("rules: %s", rules)
	}
	applyTransparentRouting() // nothing changed: not loaded again
	if b, _ := os.ReadFile(dir + "/rules.txt"); string(b) != string(rules) {
		t.Fatal("the rules were loaded again")
	}

	// the lookup of the original destination goes through the helper
	if h, p, err := lookupOriginalDst("10.0.0.2:5555"); err != nil || h != "8.8.8.8" || p != "853" {
		t.Fatalf("lookup: %s %s %v", h, p, err)
	}
	if _, _, err := lookupOriginalDst("10.0.0.2:1"); err == nil {
		t.Fatal("unknown connection")
	}

	// the interface goes away: the rules are removed and the status says why
	fakeServices(t, activeService{ID: "wifi", Name: "Wi-Fi", Iface: "en0"})
	applyTransparentRouting()
	if st := transparentStatus(); st.Loaded || st.Hint == "" || len(st.Interfaces) != 0 {
		t.Fatalf("status without a matching service: %+v", st)
	}
	if b, _ := os.ReadFile(dir + "/calls.txt"); !strings.Contains(string(b), "-F all") {
		t.Fatalf("the anchor was not flushed: %s", b)
	}

	// the option is turned off: the helper is told to end
	configuration.TransparentRoute = nil
	applyTransparentRouting()
	if st := transparentStatus(); st.Loaded || st.NeedsAuth || len(st.Configured) != 0 {
		t.Fatalf("status when off: %+v", st)
	}
	if helperAlive() {
		t.Fatal("the helper is still there")
	}
}

func TestApplyTransparentRoutingWithoutTheHelper(t *testing.T) {
	apiFixture(t)
	_, stop := fakeHelper(t)
	defer stop()
	pfSocketFn = func() string { return t.TempDir() + "/nobody.sock" }
	fakeServices(t, activeService{ID: "net.example.vpn", Name: "Example VPN", Iface: "utun9", Dynamic: true})
	oldRun := runOsascript
	runOsascript = func(string) ([]byte, error) {
		t.Error("a dialog was opened in mode never")
		return nil, errors.New("no")
	}
	defer func() { runOsascript = oldRun }()

	configuration.TransparentRoute = []string{"example"}
	configuration.TransparentMode = "never"
	applyTransparentRouting()
	if st := transparentStatus(); st.Loaded || !st.NeedsAuth || st.Mode != "never" {
		t.Fatalf("status: %+v", st)
	}
	waitIdle(t)
	removeTransparentRouting() // no helper: nothing to do
}

func waitIdle(t *testing.T) {
	t.Helper()
	for i := 0; i < 200; i++ {
		authMu.Lock()
		busy := authBusy
		authMu.Unlock()
		if !busy {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the authorization never ended")
}

func TestTransparentTargetsAndModes(t *testing.T) {
	apiFixture(t)
	fakeServices(t,
		activeService{ID: "net.example.vpn", Name: "Example VPN", Iface: "utun9", Dynamic: true},
		activeService{ID: "wifi", Name: "Wi-Fi", Iface: "en0"},
		activeService{ID: "weird", Name: "Weird", Iface: "bad iface"})
	for sel, want := range map[string]int{"example": 1, "EN0": 1, "wi-fi": 1, "net.example": 1, "utun": 1, "weird": 0, "": 0, "zzz": 0} {
		if got := len(transparentTargets([]string{sel})); got != want {
			t.Errorf("selector %q: %d targets, want %d", sel, got, want)
		}
	}
	if got := len(transparentTargets([]string{"example", "wifi", "wi-fi"})); got != 2 {
		t.Errorf("several selectors: %d", got)
	}
	for in, want := range map[string]string{"": "ask", "auto": "auto", "never": "never", "bogus": "ask"} {
		configuration.TransparentMode = in
		if got := transparentMode(); got != want {
			t.Errorf("mode %q = %q, want %q", in, got, want)
		}
	}
	if d := describeTargets([]activeService{{Name: "Example VPN", Iface: "utun9"}, {Name: "Wi-Fi", Iface: "en0"}}); !strings.Contains(d, "«Example VPN» (interfaccia utun9)") || !strings.Contains(d, "Wi-Fi") {
		t.Errorf("description: %s", d)
	}
}

func TestRunPFHelperRefusesToStartWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	if runPFHelper([]string{"/var/run/proxyroute-1.sock", "501", "1"}) != 2 || runPFHelper(nil) != 2 {
		t.Fatal("the helper must refuse to run without root and with bad arguments")
	}
}

func TestHelperFlushAndRelease(t *testing.T) {
	dir, stop := fakeHelper(t)
	defer stop()
	h := &pfHelper{}
	if err := h.flush(); err != nil { // nothing loaded
		t.Fatal(err)
	}
	if err := h.load([]string{"utun3"}); err != nil {
		t.Fatal(err)
	}
	if err := h.flush(); err != nil || h.loaded {
		t.Fatalf("flush: %v loaded=%v", err, h.loaded)
	}
	h.load([]string{"utun3"})
	h.release()
	b, _ := os.ReadFile(dir + "/calls.txt")
	if !strings.Contains(string(b), "-F all") || !strings.Contains(string(b), "released") || h.token != "" {
		t.Fatalf("release: %s token=%q", b, h.token)
	}
	if _, err := h.lookup("not-an-address"); err == nil {
		t.Fatal("bad source address")
	}
}
