package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func init() { secretIterations = 1000 } // the tests derive many keys

func TestRecoveryKeyFormat(t *testing.T) {
	priv := make([]byte, 32)
	rand.Read(priv)
	text := formatRecoveryKey(priv)
	if !strings.HasPrefix(text, "GSPR-") || !looksLikeRecoveryKey(text) || looksLikeRecoveryKey("a master password") {
		t.Fatalf("format: %s", text)
	}
	back, err := parseRecoveryKey(text)
	if err != nil || !bytes.Equal(back, priv) {
		t.Fatalf("parse: %v", err)
	}
	// case, spaces and missing dashes do not matter
	if b, err := parseRecoveryKey(strings.ToLower(strings.ReplaceAll(text, "-", " "))); err != nil || !bytes.Equal(b, priv) {
		t.Fatalf("lenient parse: %v", err)
	}
	// a typing mistake is caught
	bad := []byte(text)
	i := len(bad) - 6
	if bad[i] == 'A' {
		bad[i] = 'B'
	} else {
		bad[i] = 'A'
	}
	if _, err := parseRecoveryKey(string(bad)); err == nil {
		t.Fatal("a typo went through")
	}
	for _, s := range []string{"", "GSPR-", "GSPR-AAAA", "not a key at all"} {
		if _, err := parseRecoveryKey(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestSealAndOpenRecovery(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := make([]byte, 32)
	rand.Read(key)
	blob, err := sealToRecovery(priv.PublicKey(), key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openRecovery(blob, priv)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("open: %v", err)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := openRecovery(blob, other); err == nil {
		t.Fatal("another recovery key opened it")
	}
	blob.Sealed = blob.Sealed[:len(blob.Sealed)-4] + "AAAA"
	if _, err := openRecovery(blob, priv); err == nil {
		t.Fatal("a damaged file was opened")
	}
}

// secretsEnv is a configuration protected by a master password, in a
// directory of its own.
func secretsEnv(t *testing.T, password string) {
	t.Helper()
	resetEnv(t, nil, nil)
	t.Chdir(t.TempDir())
	oldConfig := configuration
	t.Cleanup(func() {
		configuration = oldConfig
		clearConfigCrypto()
		recoveredMu.Lock()
		recoveredSession = false
		recoveredMu.Unlock()
	})
	t.Setenv(noKeychainEnv, "1")
	enc, err := encryptSecret(password, []byte("Address: 127.0.0.1:9999\nRoutes: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFileAtomic(encryptedConfig, enc); err != nil {
		t.Fatal(err)
	}
	t.Setenv(secretEnv, password) // how loadConfiguration is given the password
	loadConfiguration()
	t.Setenv(secretEnv, "")
}

func readEncrypted(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(encryptedConfig)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestChangingTheMasterPassword(t *testing.T) {
	secretsEnv(t, "the old password")
	saltBefore, _ := secretSalt(readEncrypted(t))

	if err := changeMasterPassword("not the old one", "a brand new password"); err == nil {
		t.Fatal("a wrong old password was accepted")
	}
	if err := changeMasterPassword("the old password", "short"); err == nil {
		t.Fatal("a short password was accepted")
	}
	if _, err := decryptSecret("the old password", readEncrypted(t)); err != nil {
		t.Fatal("a refused change touched the file")
	}
	if err := changeMasterPassword("the old password", "a brand new password"); err != nil {
		t.Fatal(err)
	}
	after := readEncrypted(t)
	if _, err := decryptSecret("the old password", after); err == nil {
		t.Fatal("the old password still opens the file")
	}
	plain, err := decryptSecret("a brand new password", after)
	if err != nil || !strings.Contains(string(plain), "127.0.0.1:9999") {
		t.Fatalf("new password: %v %s", err, plain)
	}
	if saltAfter, _ := secretSalt(after); bytes.Equal(saltBefore, saltAfter) {
		t.Fatal("the salt was kept")
	}
	// the running proxy uses the new key: saving works and is readable with the new password
	configMu.Lock()
	configuration.Address = "127.0.0.1:7777"
	err = persistConfigurationLocked()
	configMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := decryptSecret("a brand new password", readEncrypted(t)); err != nil || !strings.Contains(string(plain), "7777") {
		t.Fatalf("saving after the change: %v", err)
	}
	if verifyMasterPassword("the old password") || !verifyMasterPassword("a brand new password") {
		t.Fatal("verification")
	}
}

func TestRecoveryKeyOpensTheConfigurationAndSurvivesPasswordChanges(t *testing.T) {
	secretsEnv(t, "the old password")
	if on, _ := recoveryInfo(); on {
		t.Fatal("a recovery key exists from the start")
	}
	key, err := createRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if on, created := recoveryInfo(); !on || created.IsZero() {
		t.Fatal("recovery info")
	}
	if raw, _ := os.ReadFile(recoveryFile); strings.Contains(string(raw), key) || strings.Contains(string(raw), "GSPR") {
		t.Fatal("the recovery key is in the recovery file")
	}

	// the password changes: the same recovery key still works, with no need of it
	if err := changeMasterPassword("the old password", "a second password!"); err != nil {
		t.Fatal(err)
	}
	// "restart": nothing in memory, only the files and the recovery key
	clearConfigCrypto()
	data := readEncrypted(t)
	if _, err := unlockConfigWithPassword(data, "the old password"); err == nil {
		t.Fatal("the old password opened it")
	}
	plain, err := unlockConfigWithPassword(data, key) // typed where the password goes
	if err != nil || !strings.Contains(string(plain), "127.0.0.1:9999") {
		t.Fatalf("recovery: %v", err)
	}
	if !isRecoveredSession() {
		t.Fatal("not marked as recovered")
	}
	// now the owner sets a new password without knowing the old one
	if err := changeMasterPassword("", "the third password"); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if isRecoveredSession() {
		t.Fatal("still marked as recovered")
	}
	if _, err := decryptSecret("the third password", readEncrypted(t)); err != nil {
		t.Fatal(err)
	}
	// and the recovery key goes on working
	clearConfigCrypto()
	if _, err := unlockConfigWithPassword(readEncrypted(t), key); err != nil {
		t.Fatalf("recovery after the third password: %v", err)
	}
	// without being recovered, the old password is needed again
	clearConfigCrypto()
	unlockConfigWithPassword(readEncrypted(t), "the third password")
	if err := changeMasterPassword("", "a fourth password!"); err == nil {
		t.Fatal("an empty old password was accepted")
	}

	// a wrong key, a typo, no recovery file
	other := formatRecoveryKey(bytes.Repeat([]byte{7}, 32))
	if _, err := unlockConfigWithRecoveryKey(readEncrypted(t), other); err == nil {
		t.Fatal("another recovery key opened it")
	}
	if err := removeRecoveryKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := unlockConfigWithRecoveryKey(readEncrypted(t), key); err == nil {
		t.Fatal("a removed recovery key worked")
	}
}

func TestStaleRecoveryFileIsSealedAgain(t *testing.T) {
	secretsEnv(t, "the old password")
	key, _ := createRecoveryKey()
	// simulate a crash between the two writes of a password change: the
	// configuration is under the new key, the recovery file still holds the old one
	stale, _ := os.ReadFile(recoveryFile)
	if err := changeMasterPassword("the old password", "a second password!"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(recoveryFile, stale, 0o600)
	if _, err := unlockConfigWithRecoveryKey(readEncrypted(t), key); err == nil {
		t.Fatal("a stale recovery file opened the configuration")
	}
	healRecovery() // what start-up does
	clearConfigCrypto()
	if _, err := unlockConfigWithRecoveryKey(readEncrypted(t), key); err != nil {
		t.Fatalf("after healing: %v", err)
	}
}

func TestSecurityAPI(t *testing.T) {
	secretsEnv(t, "the old password")
	call := func(method, path string, body any) (int, map[string]any) {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req := httptest.NewRequest(method, path, rd)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		apiMux.ServeHTTP(w, req)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, st := call("GET", "/api/security", nil); code != 200 || st["recoveryEnabled"] != false || st["recovered"] != false {
		t.Fatalf("status: %d %v", code, st)
	}
	// a wrong password is refused, and keeps being, then the door shuts for a minute
	pwTries.mu.Lock()
	pwTries.times = nil
	pwTries.mu.Unlock()
	for i := 0; i < 5; i++ {
		if code, _ := call("POST", "/api/security/recovery", map[string]string{"password": "guess"}); code != 403 {
			t.Fatalf("wrong password: %d", code)
		}
	}
	if code, _ := call("POST", "/api/security/recovery", map[string]string{"password": "the old password"}); code != 429 {
		t.Fatalf("attempts are not limited: %d", code)
	}
	pwTries.mu.Lock()
	pwTries.times = nil
	pwTries.mu.Unlock()

	code, out := call("POST", "/api/security/recovery", map[string]string{"password": "the old password"})
	key, _ := out["key"].(string)
	if code != 200 || !strings.HasPrefix(key, "GSPR-") {
		t.Fatalf("create: %d %v", code, out)
	}
	code, st := call("GET", "/api/security", nil)
	if st["recoveryEnabled"] != true || strings.Contains(toJSON(st), key) {
		t.Fatalf("status after: %v", st)
	}
	if code, _ := call("POST", "/api/security/password", map[string]string{"old": "the old password", "new": "short"}); code != 400 {
		t.Fatalf("short: %d", code)
	}
	if code, _ := call("POST", "/api/security/password", map[string]string{"old": "the old password", "new": "a brand new password"}); code != 200 {
		t.Fatalf("change: %d", code)
	}
	if code, _ := call("POST", "/api/security/recovery/remove", map[string]string{"password": "the old password"}); code != 403 {
		t.Fatalf("remove with the old password: %d", code)
	}
	if code, _ := call("POST", "/api/security/recovery/remove", map[string]string{"password": "a brand new password"}); code != 200 {
		t.Fatalf("remove: %d", code)
	}
	if on, _ := recoveryInfo(); on {
		t.Fatal("recovery file still there")
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
