//go:build darwin || linux

package main

import (
	"fmt"
	"os"
	"strings"
)

const hostsFile = "/etc/hosts"

// ensureHostsEntry makes sure that /etc/hosts maps the PAC host to 127.0.0.1.
func ensureHostsEntry(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	entry := "127.0.0.1 " + host
	data, err := os.ReadFile(hostsFile)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == entry {
			return nil
		}
	}
	f, err := os.OpenFile(hostsFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "\n%s\n", entry); err != nil {
		return err
	}
	return nil
}

// removeHostsEntry removes the PAC host mapping from /etc/hosts.
func removeHostsEntry(host string) error {
	if host == "" {
		return nil
	}
	entry := "127.0.0.1 " + host
	data, err := os.ReadFile(hostsFile)
	if err != nil {
		return err
	}
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == entry {
			continue
		}
		kept = append(kept, line)
	}
	return os.WriteFile(hostsFile, []byte(strings.Join(kept, "\n")), 0644)
}
