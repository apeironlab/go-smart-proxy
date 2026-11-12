package main

import "log"

// chromePolicyRemover is replaced in tests: they must not touch the real Chrome preferences.
var chromePolicyRemover = removeChromePolicy

// removeLegacyChromePolicy undoes the "Force Chrome" setting of older
// versions: it removes the policy keys they wrote and forgets the setting.
func removeLegacyChromePolicy() {
	configMu.Lock()
	legacy := configuration.ForceChrome
	configMu.Unlock()
	if !legacy {
		return
	}
	chromePolicyRemover()
	configMu.Lock()
	configuration.ForceChrome = false
	err := persistConfigurationLocked()
	configMu.Unlock()
	if err != nil {
		log.Printf("Cannot forget the old Chrome policy setting: %v", err)
		return
	}
	log.Printf("The Chrome proxy policy of older versions was removed")
}
