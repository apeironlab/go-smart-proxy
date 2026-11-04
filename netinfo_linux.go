//go:build linux

package main

import "os"

// readRouteTable returns the IPv4 routing table.
func readRouteTable() ([]routeEntry, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	return parseLinuxRoutes(string(b)), nil
}
