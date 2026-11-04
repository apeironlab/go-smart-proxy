//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// readRouteTable returns the IPv4 routing table, read with `route print -4`
// (present on every Windows version; only its numeric rows are parsed).
func readRouteTable() ([]routeEntry, error) {
	cmd := exec.Command("route", "print", "-4")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseWindowsRoutes(string(out)), nil
}
