//go:build darwin

package main

import (
	"log"
	"net"
	"os/exec"
	"strings"
)

const chromeDomain = "com.google.Chrome"

// chromePolicyKeys are the only preference keys this program manages in
// Chrome's domain. Everything else in the user's Chrome preferences is left
// untouched.
var chromePolicyKeys = []string{"ProxyMode", "ProxyServer", "ProxyBypassList"}

// applyChromePolicy forces Chrome to use this proxy via its ProxyMode
// policy. This does not touch the system proxy settings nor the VPN.
//
// The keys are written with `defaults`, so they go through cfprefsd (which is
// what Chrome reads) and the rest of the preference domain is preserved.
func applyChromePolicy() {
	configMu.Lock()
	enabled := configuration.ForceChrome
	address := configuration.Address
	configMu.Unlock()
	if !enabled {
		return
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" || !safeConfigToken(host) || !safeConfigToken(port) {
		host = "127.0.0.1"
		port = "3128"
	}
	values := map[string]string{
		"ProxyMode":       "fixed_servers",
		"ProxyServer":     net.JoinHostPort(host, port),
		"ProxyBypassList": "localhost;127.0.0.1;*.local;169.254/16",
	}
	for _, key := range chromePolicyKeys {
		if out, err := exec.Command("defaults", "write", chromeDomain, key, "-string", values[key]).CombinedOutput(); err != nil {
			log.Printf("Error writing Chrome policy %s: %v (%s)", key, err, strings.TrimSpace(string(out)))
			return
		}
	}
	log.Printf("Chrome policy set: proxy %s (restart Chrome to apply)", values["ProxyServer"])
}

// removeChromePolicy removes the Chrome proxy policy keys set by
// applyChromePolicy, leaving the other preferences intact.
func removeChromePolicy() {
	for _, key := range chromePolicyKeys {
		out, err := exec.Command("defaults", "delete", chromeDomain, key).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "does not exist") {
			log.Printf("Error removing Chrome policy %s: %v (%s)", key, err, strings.TrimSpace(string(out)))
		}
	}
}
