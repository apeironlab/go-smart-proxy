//go:build darwin

package main

import (
	"log"
	"os/exec"
	"strings"
)

// Older versions could write a Chrome proxy policy ("Force Chrome"). Chrome
// ignores it on a Mac that is not managed, so the feature is gone; this removes
// the three keys those versions wrote, once, when the old setting is found.
var chromeLegacyKeys = []string{"ProxyMode", "ProxyServer", "ProxyBypassList"}

func removeChromePolicy() {
	for _, key := range chromeLegacyKeys {
		out, err := exec.Command("defaults", "delete", "com.google.Chrome", key).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "does not exist") {
			log.Printf("Error removing the old Chrome policy %s: %v (%s)", key, err, strings.TrimSpace(string(out)))
		}
	}
}
