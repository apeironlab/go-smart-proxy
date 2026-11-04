package main

import (
	"os"
	"strings"
	"testing"
)

func TestRecoveryWithoutAKeyOrAFile(t *testing.T) {
	secretsEnv(t, "the master password")
	clearConfigCrypto()
	if _, err := createRecoveryKey(); err == nil {
		t.Error("a recovery key for a locked configuration")
	}
	if err := changeMasterPassword("the master password", "another long password"); err == nil {
		t.Error("changed the password of a locked configuration")
	}
	if verifyMasterPassword("the master password") {
		t.Error("verified against nothing")
	}
	healRecovery() // locked: nothing to do
	if err := resealRecovery(make([]byte, 32)); err != nil {
		t.Errorf("no recovery file is not an error: %v", err)
	}
	if ok, _ := recoveryInfo(); ok {
		t.Error("recovery reported with no file")
	}
	if err := removeRecoveryKey(); err != nil {
		t.Errorf("removing what does not exist: %v", err)
	}
}

func TestRecoveryKeyLifecycle(t *testing.T) {
	secretsEnv(t, "the master password")
	text, err := createRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if ok, when := recoveryInfo(); !ok || when.IsZero() {
		t.Errorf("recoveryInfo = %v %v", ok, when)
	}
	if err := changeMasterPassword("wrong", "another long password"); err == nil {
		t.Error("changed with the wrong old password")
	}
	if err := changeMasterPassword("the master password", "short"); err != errPasswordTooShort {
		t.Errorf("short: %v", err)
	}
	if err := changeMasterPassword("the master password", "another long password"); err != nil {
		t.Fatal(err)
	}
	// the recovery file follows the new key
	data, _ := os.ReadFile(encryptedConfig)
	if _, err := unlockConfigWithRecoveryKey(data, text); err != nil {
		t.Errorf("the recovery key stopped working after a password change: %v", err)
	}
	if !isRecoveredSession() {
		t.Error("not a recovered session")
	}
	// healing: make the file hold an old key, then heal
	other := make([]byte, 32)
	if err := resealRecovery(other); err != nil {
		t.Fatal(err)
	}
	healRecovery()
	if _, err := unlockConfigWithRecoveryKey(data, text); err != nil {
		t.Errorf("healRecovery did not repair the file: %v", err)
	}
	// things that must not unlock
	for name, in := range map[string]string{"typo": "GSPR-AAAA-AAAA", "garbage": "nonsense"} {
		if _, err := unlockConfigWithRecoveryKey(data, in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := unlockConfigWithRecoveryKey([]byte("junk"), text); err == nil {
		t.Error("junk unlocked")
	}
	// a damaged recovery file
	os.WriteFile(recoveryFile, []byte("{"), 0o600)
	if _, err := unlockConfigWithRecoveryKey(data, text); err == nil || !strings.Contains(err.Error(), "recovery file") {
		t.Errorf("damaged file: %v", err)
	}
	if err := resealRecovery(other); err == nil {
		t.Error("resealed a damaged file")
	}
	healRecovery() // logs and carries on
	if err := removeRecoveryKey(); err != nil {
		t.Error(err)
	}
	if ok, _ := recoveryInfo(); ok {
		t.Error("still reported after removal")
	}
}
