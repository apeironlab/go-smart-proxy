//go:build !darwin && !linux

package main

import "fmt"

const hostsFile = "hosts"

func ensureHostsEntry(host string) error {
	return fmt.Errorf("not supported on this platform")
}

func removeHostsEntry(host string) error {
	return nil
}
