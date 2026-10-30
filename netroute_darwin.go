//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// defaultRouteInfo returns the gateway and the interface of the real default
// route, straight from the routing table. This is reliable even when VPN
// clients leave their utun interfaces around while disconnected: the default
// route is what actually carries the traffic.
func defaultRouteInfo() (gateway, ifaceName string, err error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		k, v, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "gateway":
			gateway = strings.TrimSpace(v)
		case "interface":
			ifaceName = strings.TrimSpace(v)
		}
	}
	if ifaceName == "" {
		return "", "", fmt.Errorf("no default route interface")
	}
	return gateway, ifaceName, nil
}
