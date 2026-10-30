//go:build darwin

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
)

// chromePolicyPath is the user-level managed preferences plist Chrome reads
// for policies on macOS.
func chromePolicyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Preferences", "com.google.Chrome.plist"), nil
}

// applyChromePolicy forces Chrome to use this proxy via its ProxyMode
// policy. This does not touch the system proxy settings nor the VPN.
func applyChromePolicy() {
	if !configuration.ForceChrome {
		return
	}
	path, err := chromePolicyPath()
	if err != nil {
		log.Printf("Error locating Chrome policy file: %+v", err)
		return
	}
	host, port, err := net.SplitHostPort(configuration.Address)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
		port = "3128"
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>ProxyMode</key>
	<string>fixed_servers</string>
	<key>ProxyServer</key>
	<string>%s:%s</string>
	<key>ProxyBypassList</key>
	<string>localhost;127.0.0.1;*.local;169.254/16</string>
</dict>
</plist>
`, host, port)
	if err := os.WriteFile(path, []byte(plist), 0644); err != nil {
		log.Printf("Error writing Chrome policy: %+v", err)
		return
	}
	log.Printf("Chrome policy set: proxy %s:%s (restart Chrome to apply)", host, port)
}

// removeChromePolicy removes the Chrome proxy policy.
func removeChromePolicy() {
	path, err := chromePolicyPath()
	if err != nil {
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("Error removing Chrome policy: %+v", err)
	}
}
