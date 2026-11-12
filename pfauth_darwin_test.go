//go:build darwin

package main

import (
	"errors"
	"strings"
	"testing"
)

func fakeOsascript(t *testing.T, f func(script string) ([]byte, error)) {
	t.Helper()
	old := runOsascript
	runOsascript = f
	t.Cleanup(func() { runOsascript = old })
}

func TestAskTransparent(t *testing.T) {
	for out, want := range map[string]string{
		"button returned:Attiva, gave up:false":           "yes",
		"button returned:Non chiedere più, gave up:false": "never",
		"button returned:Non ora, gave up:false":          "no",
		"button returned:Attiva, gave up:true":            "no",
		"":                                                "no",
	} {
		fakeOsascript(t, func(script string) ([]byte, error) {
			if !strings.Contains(script, "Example VPN") || !strings.Contains(script, `\n`) {
				t.Errorf("the dialog does not name the service: %s", script)
			}
			return []byte(out), nil
		})
		if got := askTransparent("«Example VPN» (interfaccia utun9)"); got != want {
			t.Errorf("%q -> %q, want %q", out, got, want)
		}
	}
	fakeOsascript(t, func(string) ([]byte, error) { return nil, errors.New("User canceled. (-128)") })
	if askTransparent("x") != "no" {
		t.Error("a cancelled dialog is a no")
	}
}

func TestStartHelperReportsWhatHappened(t *testing.T) {
	old := helperStartTries
	helperStartTries = 1
	defer func() { helperStartTries = old }()
	pfSocketFn = func() string { return t.TempDir() + "/none.sock" }
	defer func() { pfSocketFn = func() string { return "" } }()

	var script string
	fakeOsascript(t, func(s string) ([]byte, error) { script = s; return nil, errors.New("exit status 1") })
	if err := startHelper("«X» (interfaccia utun1)"); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("failure: %v", err)
	}
	for _, want := range []string{"with administrator privileges", "--pf-helper", "/Library/PrivilegedHelperTools/proxyroute-helper", "chmod 755", "utun1"} {
		if !strings.Contains(script, want) {
			t.Errorf("the command lacks %q:\n%s", want, script)
		}
	}
	fakeOsascript(t, func(string) ([]byte, error) { return []byte("User canceled. (-128)"), errors.New("exit status 1") })
	if err := startHelper("x"); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("cancel: %v", err)
	}
	fakeOsascript(t, func(string) ([]byte, error) { return nil, nil })
	if err := startHelper("x"); err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("no helper: %v", err)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote(`it's a "path"`); got != `'it'\''s a "path"'` {
		t.Fatalf("got %s", got)
	}
}

func TestRequestHelperAsksOnceAndRemembersTheAnswer(t *testing.T) {
	apiFixture(t)
	authMu.Lock()
	authDeclined, authFailedAt = map[string]bool{}, authFailedAt.AddDate(-1, 0, 0)
	authMu.Unlock()
	targets := []activeService{{Name: "Example VPN", Iface: "utun9"}}

	asked := 0
	fakeOsascript(t, func(string) ([]byte, error) {
		asked++
		return []byte("button returned:Non ora, gave up:false"), nil
	})
	requestHelper(targets, "utun9")
	waitIdle(t)
	requestHelper(targets, "utun9") // declined for this connection: not asked again
	waitIdle(t)
	if asked != 1 {
		t.Fatalf("asked %d times", asked)
	}

	// "never ask again" is kept in the configuration
	fakeOsascript(t, func(string) ([]byte, error) {
		return []byte("button returned:Non chiedere più, gave up:false"), nil
	})
	requestHelper(targets, "utun10")
	waitIdle(t)
	if configuration.TransparentMode != "never" {
		t.Fatalf("mode = %q", configuration.TransparentMode)
	}

	// authentication that fails is not retried at once
	configuration.TransparentMode = "auto"
	helperStartTries = 1
	defer func() { helperStartTries = 50 }()
	pfSocketFn = func() string { return t.TempDir() + "/none.sock" }
	calls := 0
	fakeOsascript(t, func(string) ([]byte, error) { calls++; return nil, errors.New("exit status 1") })
	requestHelper(targets, "utun11")
	waitIdle(t)
	requestHelper(targets, "utun12")
	waitIdle(t)
	if calls != 1 {
		t.Fatalf("the authentication was tried %d times", calls)
	}
}

func TestAuthorizeTransparentGoesStraightToTheAuthentication(t *testing.T) {
	apiFixture(t)
	authMu.Lock()
	authDeclined["x"] = true
	authMu.Unlock()
	helperStartTries = 1
	defer func() { helperStartTries = 50 }()
	pfSocketFn = func() string { return t.TempDir() + "/none.sock" }
	fakeServices(t, activeService{ID: "net.example.vpn", Name: "Example VPN", Iface: "utun9", Dynamic: true})
	configuration.TransparentRoute = []string{"example"}
	var script string
	fakeOsascript(t, func(s string) ([]byte, error) { script = s; return nil, errors.New("exit status 1") })
	authorizeTransparent()
	waitIdle(t)
	if !strings.Contains(script, "do shell script") || !strings.Contains(script, "Example VPN") {
		t.Fatalf("script: %s", script)
	}
	if len(authDeclined) != 0 {
		t.Fatal("the earlier refusals must be forgotten")
	}
}
