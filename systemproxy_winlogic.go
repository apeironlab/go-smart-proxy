package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
)

// The logic of the Windows system proxy, apart from the registry it is written
// to, so that it is the same everywhere and can be tested anywhere.
//
// The settings are the per-user "Internet Options" ones that browsers, .NET and
// most programs read. While the proxy is on they are: proxy on, pointing here,
// automatic configuration (a PAC, "detect settings") off: a PAC would take
// precedence over a manual proxy, as on macOS. What was there before is kept in
// a file and put back when the proxy is switched off or quits, so that a closed
// proxy does not leave the system pointing at nothing.

// winProxySettings is what is read from and written to the system.
type winProxySettings struct {
	Enable        bool   `json:"enable"`
	Server        string `json:"server"`
	Override      string `json:"override"`
	AutoConfigURL string `json:"autoConfigUrl"`
	AutoDetect    bool   `json:"autoDetect"`
}

// winProxyStore is the system's proxy settings.
type winProxyStore interface {
	read() (winProxySettings, error)
	write(winProxySettings) error
}

const winProxyBackup = "system_proxy_backup.json"

// winProxyTarget returns the host and port to point the system at.
func winProxyTarget(address string) (host, port string) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" || !safeConfigToken(host) || !safeConfigToken(port) {
		return "127.0.0.1", "3128"
	}
	return host, port
}

// winProxyOverride is the list of what is not sent through the proxy.
const winProxyOverride = "localhost;127.0.0.1;<local>"

func winWanted(address string) winProxySettings {
	host, port := winProxyTarget(address)
	return winProxySettings{Enable: true, Server: net.JoinHostPort(host, port), Override: winProxyOverride}
}

func (a winProxySettings) isOurs(want winProxySettings) bool {
	return a.Enable && a.Server == want.Server && a.AutoConfigURL == "" && !a.AutoDetect
}

// applyWinProxy points the system at the proxy. It reports whether it changed
// anything.
func applyWinProxy(st winProxyStore, address, backupPath string) (bool, error) {
	want := winWanted(address)
	cur, err := st.read()
	if err != nil {
		return false, err
	}
	if cur.isOurs(want) {
		return false, nil
	}
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		keep := cur
		if cur.Enable && cur.Server == want.Server { // ours, left by a proxy that did not quit cleanly
			keep = winProxySettings{}
		}
		b, _ := json.Marshal(keep)
		if err := os.WriteFile(backupPath, b, 0o600); err != nil {
			return false, fmt.Errorf("cannot keep the previous proxy settings: %w", err)
		}
	}
	// Keep what the user set that is not ours to change.
	want.Override = cur.Override
	if want.Override == "" || !cur.Enable {
		want.Override = winProxyOverride
	}
	return true, st.write(want)
}

// restoreWinProxy puts back what was there before the proxy took over.
func restoreWinProxy(st winProxyStore, address, backupPath string) error {
	b, err := os.ReadFile(backupPath)
	if os.IsNotExist(err) {
		// No backup: leave it alone unless it points at us, then switch it off.
		cur, rerr := st.read()
		if rerr == nil && cur.isOurs(winWanted(address)) {
			cur.Enable = false
			return st.write(cur)
		}
		return nil
	}
	if err != nil {
		return err
	}
	var old winProxySettings
	if err := json.Unmarshal(b, &old); err != nil {
		return err
	}
	if err := st.write(old); err != nil {
		return err
	}
	return os.Remove(backupPath)
}

func winStateJSON(s winProxySettings) systemProxyStateJSON {
	host, port := s.Server, 0
	if h, p, err := net.SplitHostPort(s.Server); err == nil {
		host = h
		port, _ = strconv.Atoi(p)
	}
	st := systemProxyStateJSON{
		HTTPEnable: s.Enable, HTTPProxy: host, HTTPPort: port,
		HTTPSEnable: s.Enable, HTTPSProxy: host, HTTPSPort: port,
		PACEnable: s.AutoConfigURL != "", PACURL: s.AutoConfigURL, Exceptions: []string{},
	}
	for _, e := range splitSemicolons(s.Override) {
		st.Exceptions = append(st.Exceptions, e)
	}
	b, _ := json.Marshal(s)
	st.Raw = string(b)
	return st
}

func splitSemicolons(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ';' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// ---- Chrome ------------------------------------------------------------

// chromeWinPolicy are the values written under Chrome's policy key.
func chromeWinPolicy(address string) map[string]string {
	host, port := winProxyTarget(address)
	return map[string]string{
		"ProxyMode":       "fixed_servers",
		"ProxyServer":     net.JoinHostPort(host, port),
		"ProxyBypassList": "localhost;127.0.0.1;*.local;169.254/16",
	}
}

var chromeWinKeys = []string{"ProxyMode", "ProxyServer", "ProxyBypassList"}

// ---- notifications -----------------------------------------------------

// windowsToastScript shows a toast. The text is not in the script: it travels in
// the environment (GSP_TITLE, GSP_BODY), so nothing a request or a contact
// sends can be taken for code.
const windowsToastScript = `$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$t = [System.Security.SecurityElement]::Escape($env:GSP_TITLE)
$b = [System.Security.SecurityElement]::Escape($env:GSP_BODY)
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))`

// windowsToastCommand is the command that shows a notification.
func windowsToastCommand(title, body string) (name string, args []string, env []string) {
	clean := func(s string) string {
		out := make([]rune, 0, len(s))
		for _, r := range s {
			if r == '\n' || r == '\r' || r == '\t' {
				r = ' '
			}
			if r >= 0x20 && r != 0x7f {
				out = append(out, r)
			}
		}
		if len(out) > 300 {
			out = out[:300]
		}
		return string(out)
	}
	return "powershell.exe",
		[]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", windowsToastScript},
		[]string{"GSP_TITLE=" + clean(title), "GSP_BODY=" + clean(body)}
}
