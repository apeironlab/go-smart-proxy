package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"

	"proxy/relay"
)

var deviceAdjectives = []string{
	"amber", "brave", "bright", "calm", "clever", "cosmic", "gentle", "green",
	"happy", "lucky", "noble", "quiet", "rapid", "silver", "swift", "warm",
	"wild", "wise", "blue", "bold", "crisp", "fresh", "kind", "steady",
}

var deviceAnimals = []string{
	"otter", "falcon", "panda", "tiger", "fox", "wolf", "eagle", "dolphin",
	"koala", "lynx", "raven", "seal", "bear", "crane", "hare", "moth",
	"orca", "puma", "swan", "yak", "heron", "badger", "gecko", "ibis",
}

func randomIndex(n int) int {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(b[0]) % n
}

// randomDeviceID returns a human-friendly but unique device code, such as
// "quiet-otter-7f3a". It is stored in the encrypted configuration.
func randomDeviceID() string {
	var suffix [2]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		suffix[0], suffix[1] = 0xab, 0xcd
	}
	return deviceAdjectives[randomIndex(len(deviceAdjectives))] + "-" +
		deviceAnimals[randomIndex(len(deviceAnimals))] + "-" +
		hex.EncodeToString(suffix[:])
}

// ensureRelayDevice assigns this installation a device code if the relay is
// configured and the configuration does not have a valid one yet.
func ensureRelayDevice() {
	cfg := configuration.Relay
	if cfg == nil || cfg.Address == "" {
		return
	}
	if device, ok := relay.NormalizeDevice(cfg.Device); ok && device != "" {
		cfg.Device = device
		return
	}
	cfg.Device = randomDeviceID()
	configMu.Lock()
	err := persistConfigurationLocked()
	configMu.Unlock()
	if err != nil {
		log.Printf("WARNING: cannot save the relay device name: %v", err)
	}
	log.Printf("Relay device name: %s", cfg.Device)
}
