package main

import (
	"testing"

	"github.com/apeironlab/go-smart-proxy/relay"
)

func TestRandomDeviceID(t *testing.T) {
	for i := 0; i < 20; i++ {
		id := randomDeviceID()
		norm, ok := relay.NormalizeDevice(id)
		if !ok || norm != id {
			t.Fatalf("invalid device id %q", id)
		}
	}
}
