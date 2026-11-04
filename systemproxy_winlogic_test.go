package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeWinProxy is the registry, in memory.
type fakeWinProxy struct {
	s      winProxySettings
	writes int
}

func (f *fakeWinProxy) read() (winProxySettings, error) { return f.s, nil }
func (f *fakeWinProxy) write(s winProxySettings) error  { f.s = s; f.writes++; return nil }

func TestWindowsSystemProxyIsSetOnceAndLeftAlone(t *testing.T) {
	backup := filepath.Join(t.TempDir(), "backup.json")
	st := &fakeWinProxy{s: winProxySettings{Enable: true, Server: "corp-proxy:8080", Override: "*.corp.example;<local>", AutoConfigURL: "http://wpad/wpad.dat", AutoDetect: true}}
	changed, err := applyWinProxy(st, "127.0.0.1:3128", backup)
	if err != nil || !changed {
		t.Fatalf("apply: %v %v", changed, err)
	}
	// pointing here, and the PAC and automatic detection off: they would win
	if !st.s.Enable || st.s.Server != "127.0.0.1:3128" || st.s.AutoConfigURL != "" || st.s.AutoDetect {
		t.Fatalf("settings: %+v", st.s)
	}
	if !strings.Contains(st.s.Override, "*.corp.example") {
		t.Fatalf("the user's own exceptions were lost: %q", st.s.Override)
	}
	// called again and again (it runs every ten seconds): no writes
	for i := 0; i < 5; i++ {
		if changed, _ := applyWinProxy(st, "127.0.0.1:3128", backup); changed {
			t.Fatal("rewrote settings that were already right")
		}
	}
	if st.writes != 1 {
		t.Fatalf("%d writes", st.writes)
	}
	// someone (a VPN client, a policy) puts its own back: it is taken again,
	// and the first backup is the one that is kept
	st.s = winProxySettings{Enable: true, Server: "other:3128", AutoConfigURL: "http://vpn/pac"}
	if changed, _ := applyWinProxy(st, "127.0.0.1:3128", backup); !changed || st.s.Server != "127.0.0.1:3128" {
		t.Fatalf("not taken again: %+v", st.s)
	}
	// quitting puts back what the user had before the proxy first took over
	if err := restoreWinProxy(st, "127.0.0.1:3128", backup); err != nil {
		t.Fatal(err)
	}
	if st.s.Server != "corp-proxy:8080" || st.s.AutoConfigURL != "http://wpad/wpad.dat" || !st.s.AutoDetect || !st.s.Enable {
		t.Fatalf("restored: %+v", st.s)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("the backup stays after restoring")
	}
}

func TestWindowsProxyWithNothingBeforeIsSwitchedOffAgain(t *testing.T) {
	backup := filepath.Join(t.TempDir(), "b.json")
	st := &fakeWinProxy{}
	applyWinProxy(st, "127.0.0.1:3128", backup)
	if !st.s.Enable {
		t.Fatal("not on")
	}
	restoreWinProxy(st, "127.0.0.1:3128", backup)
	if st.s.Enable {
		t.Fatalf("still on: %+v", st.s)
	}
}

func TestWindowsProxyAfterACrashDoesNotBackUpItsOwnSetting(t *testing.T) {
	backup := filepath.Join(t.TempDir(), "b.json")
	// the proxy set itself, then died with the backup lost: the next start must
	// not take its own setting for the user's
	st := &fakeWinProxy{s: winProxySettings{Enable: true, Server: "127.0.0.1:3128", Override: "<local>", AutoDetect: true}}
	applyWinProxy(st, "127.0.0.1:3128", backup)
	restoreWinProxy(st, "127.0.0.1:3128", backup)
	if st.s.Enable {
		t.Fatalf("restoring after a crash kept the proxy on: %+v", st.s)
	}
	// and nothing is touched when the settings are somebody else's and there is no backup
	other := &fakeWinProxy{s: winProxySettings{Enable: true, Server: "corp:8080"}}
	if err := restoreWinProxy(other, "127.0.0.1:3128", filepath.Join(t.TempDir(), "none.json")); err != nil || other.writes != 0 {
		t.Fatalf("somebody else's settings were touched: %v %d", err, other.writes)
	}
}

func TestWindowsProxyTargetIsSafe(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"127.0.0.1:3128", "127.0.0.1:3128"},
		{":3128", "127.0.0.1:3128"},
		{"0.0.0.0:8080", "127.0.0.1:3128"},
		{"[::]:3128", "127.0.0.1:3128"},
		{"garbage", "127.0.0.1:3128"},
		{"host;evil:3128", "127.0.0.1:3128"}, // ";" would add a second proxy to the list
		{"10.1.2.3:8888", "10.1.2.3:8888"},
	} {
		if got := winWanted(c.in).Server; got != c.want {
			t.Errorf("%q -> %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWindowsStateForTheUI(t *testing.T) {
	st := winStateJSON(winProxySettings{Enable: true, Server: "127.0.0.1:3128", Override: "localhost;<local>", AutoConfigURL: "http://x/pac"})
	if !st.HTTPEnable || st.HTTPProxy != "127.0.0.1" || st.HTTPPort != 3128 || !st.HTTPSEnable || !st.PACEnable || st.PACURL != "http://x/pac" ||
		len(st.Exceptions) != 2 || st.Raw == "" {
		t.Fatalf("state: %+v", st)
	}
}

func TestChromeWindowsPolicy(t *testing.T) {
	p := chromeWinPolicy("127.0.0.1:3128")
	if p["ProxyMode"] != "fixed_servers" || p["ProxyServer"] != "127.0.0.1:3128" || !strings.Contains(p["ProxyBypassList"], "localhost") {
		t.Fatalf("policy: %v", p)
	}
	for _, k := range chromeWinKeys {
		if p[k] == "" {
			t.Fatalf("no value for %s", k)
		}
	}
}

func TestToastTextNeverBecomesCode(t *testing.T) {
	title := "Request from $(Remove-Item -Recurse C:\\) `calc`"
	body := "'; Start-Process calc; '\nline two\x00\x07" + strings.Repeat("x", 500)
	name, args, env := windowsToastCommand(title, body)
	script := strings.Join(args, " ")
	if name != "powershell.exe" || strings.Contains(script, "Remove-Item") || strings.Contains(script, "Start-Process") || strings.Contains(script, "calc") {
		t.Fatalf("the text is in the script:\n%s", script)
	}
	if !strings.Contains(script, "$env:GSP_TITLE") || !strings.Contains(script, "SecurityElement]::Escape") {
		t.Fatal("the script does not read and escape its text")
	}
	if len(env) != 2 || !strings.HasPrefix(env[0], "GSP_TITLE=") || strings.ContainsAny(env[1], "\n\r\x00\x07") || len(env[1]) > 320 {
		t.Fatalf("environment: %q", env)
	}
}
