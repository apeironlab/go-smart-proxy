//go:build windows

package main

import (
	"log"

	"golang.org/x/sys/windows/registry"
)

// Chrome reads its policies from this key. The proxy writes the three keys it
// manages and nothing else (the user's own policies stay as they are).
const chromePolicyKey = `Software\Policies\Google\Chrome`

// applyChromePolicy forces Chrome to use this proxy through its ProxyMode
// policy, for the current user. Chrome applies it at its next start.
func applyChromePolicy() {
	configMu.Lock()
	enabled := configuration.ForceChrome
	address := configuration.Address
	configMu.Unlock()
	if !enabled {
		return
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, chromePolicyKey, registry.SET_VALUE)
	if err != nil {
		log.Printf("Chrome policy: %v", err)
		return
	}
	defer k.Close()
	values := chromeWinPolicy(address)
	for _, name := range chromeWinKeys {
		if err := k.SetStringValue(name, values[name]); err != nil {
			log.Printf("Chrome policy %s: %v", name, err)
			return
		}
	}
	log.Printf("Chrome policy set: proxy %s (restart Chrome to apply)", values["ProxyServer"])
}

// removeChromePolicy removes the keys applyChromePolicy wrote.
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
