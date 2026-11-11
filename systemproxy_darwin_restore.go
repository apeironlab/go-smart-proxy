//go:build darwin

package main

import (
	"log"
	"net"
	"os/exec"
	"strings"
)

// restoreSystemProxy undoes what applySystemProxy wrote, but only when the
// system proxy option is off: on every service configured in System Settings
// whose proxy points at this proxy, the HTTP/HTTPS proxy is switched off.
// Services pointing elsewhere, and dynamic VPN services (owned by their
// client, which reacts to any change), are never touched. With the option
// on (e.g. at quit) the settings stay in place.
func restoreSystemProxy() {
	configMu.Lock()
	enabled := configuration.SystemProxy
	address := configuration.Address
	configMu.Unlock()
	if enabled {
		return
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		host, port = "127.0.0.1", "3128"
	}

	for _, svc := range activeServices() {
		if svc.Dynamic {
			continue
		}
		he, hse, _, hp, hsp, hport, hsport := serviceProxies(svc.ID)
		ours := (he && hp == host && hport == port) || (hse && hsp == host && hsport == port)
		if !ours {
			continue
		}
		for _, args := range [][]string{
			{"-setwebproxystate", svc.Name, "off"},
			{"-setsecurewebproxystate", svc.Name, "off"},
		} {
			if out, err := exec.Command("networksetup", args...).CombinedOutput(); err != nil {
				log.Printf("networksetup %v failed: %v (%s)", args, err, strings.TrimSpace(string(out)))
			}
		}
		log.Printf("System proxy removed from %s (%s)", svc.Name, svc.Iface)
	}
}
