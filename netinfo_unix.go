//go:build !linux && !windows

package main

import "os/exec"

// readRouteTable returns the IPv4 routing table (macOS and the BSDs).
func readRouteTable() ([]routeEntry, error) {
	out, err := exec.Command("netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		return nil, err
	}
	return parseBSDRoutes(string(out)), nil
}
