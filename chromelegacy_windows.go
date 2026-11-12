//go:build windows

package main

import (
	"log"

	"golang.org/x/sys/windows/registry"
)

// Older versions could write a Chrome proxy policy ("Force Chrome"); the
// feature is gone. This removes the keys those versions wrote under Chrome's
// policy key, once, when the old setting is found.
const chromePolicyKey = `Software\Policies\Google\Chrome`

var chromeWinKeys = []string{"ProxyMode", "ProxyServer", "ProxyBypassList"}

func removeChromePolicy() {
	k, err := registry.OpenKey(registry.CURRENT_USER, chromePolicyKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	for _, name := range chromeWinKeys {
		if err := k.DeleteValue(name); err != nil && err != registry.ErrNotExist {
			log.Printf("Chrome policy %s: %v", name, err)
		}
	}
}
