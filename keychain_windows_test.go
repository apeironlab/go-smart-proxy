//go:build windows

package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

func TestDPAPIRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	data := []byte("configuration key material")
	protected, err := dpapiProtect(data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(protected, data) {
		t.Fatal("DPAPI did not transform the data")
	}
	plain, err := dpapiUnprotect(protected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, data) {
		t.Fatalf("round trip = %q, want %q", plain, data)
	}
}

func TestWindowsKeyStore(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	key := make([]byte, secretKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	encoded := hex.EncodeToString(key)
	if err := keychainStore(keychainService, "test-account", encoded); err != nil {
		t.Fatal(err)
	}
	if !keychainExists(keychainService, "test-account") {
		t.Fatal("the DPAPI key file was not created")
	}
	got, err := keychainLoad(keychainService, "test-account")
	if err != nil {
		t.Fatal(err)
	}
	if got != encoded {
		t.Fatalf("loaded key = %q, want %q", got, encoded)
	}
	if err := keychainDelete(keychainService, "test-account"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(configKeyFile); !os.IsNotExist(err) {
		t.Fatal("the DPAPI key file was not deleted")
	}
}
