package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// The master password can be changed, and there can be a recovery key for the
// day it is forgotten.
//
// Changing it re-encrypts the configuration under a new salt and key. The
// recovery key is a private key made once and shown once: the configuration
// key is sealed to the matching public key and kept in config.recovery. Because
// sealing needs only the public key, the proxy can seal the new key after every
// change of password without ever holding the recovery key; whoever has the
// recovery key (and the sealed file) can open the configuration, and then sets
// a new password. Without the recovery key the file is useless.

const (
	recoveryFile   = "config.recovery"
	recoveryPrefix = "GSPR"
)

var (
	recoveredMu      sync.Mutex
	recoveredSession bool // unlocked with the recovery key: the old password is unknown
)

type recoveryBlob struct {
	V       int       `json:"v"`
	Pub     string    `json:"pub"` // the recovery public key (base64)
	Eph     string    `json:"eph"` // ephemeral public key of the sealing
	Nonce   string    `json:"nonce"`
	Sealed  string    `json:"sealed"` // the configuration key, encrypted
	Check   string    `json:"check"`  // fingerprint of that key, to notice when it is out of date
	Created time.Time `json:"created"`
}

var recoveryEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// formatRecoveryKey writes a private key as GSPR-XXXX-XXXX-...-CCCC, with a
// checksum so that a typing mistake is noticed.
func formatRecoveryKey(priv []byte) string {
	sum := sha256.Sum256(priv)
	raw := recoveryEnc.EncodeToString(append(append([]byte{}, priv...), sum[:2]...))
	var parts []string
	for len(raw) > 0 {
		n := 4
		if len(raw) < n {
			n = len(raw)
		}
		parts = append(parts, raw[:n])
		raw = raw[n:]
	}
	return recoveryPrefix + "-" + strings.Join(parts, "-")
}

// parseRecoveryKey reads what formatRecoveryKey wrote (case, dashes and spaces
// do not matter).
func parseRecoveryKey(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\n", "").Replace(s))
	s = strings.TrimPrefix(s, recoveryPrefix)
	b, err := recoveryEnc.DecodeString(s)
	if err != nil || len(b) != 32+2 {
		return nil, errors.New("this is not a recovery key")
	}
	sum := sha256.Sum256(b[:32])
	if subtle.ConstantTimeCompare(sum[:2], b[32:]) != 1 {
		return nil, errors.New("the recovery key has a typing mistake")
	}
	return b[:32], nil
}

// looksLikeRecoveryKey tells a recovery key from a password.
func looksLikeRecoveryKey(s string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s)), recoveryPrefix+"-")
}

func recoveryKEK(shared []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, nil, "go-smart-proxy recovery v1", 32)
}

// sealToRecovery encrypts the configuration key for the holder of the private
// key matching pub.
func sealToRecovery(pub *ecdh.PublicKey, key []byte) (recoveryBlob, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return recoveryBlob{}, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return recoveryBlob{}, err
	}
	kek, err := recoveryKEK(shared)
	if err != nil {
		return recoveryBlob{}, err
	}
	block, _ := aes.NewCipher(kek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return recoveryBlob{}, err
	}
	fp := sha256.Sum256(key)
	return recoveryBlob{
		Check: base64.StdEncoding.EncodeToString(fp[:8]),
		V:     1, Pub: base64.StdEncoding.EncodeToString(pub.Bytes()), Eph: base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()),
		Nonce: base64.StdEncoding.EncodeToString(nonce), Sealed: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, key, pub.Bytes())),
	}, nil
}

func openRecovery(b recoveryBlob, priv *ecdh.PrivateKey) ([]byte, error) {
	eph, err := base64.StdEncoding.DecodeString(b.Eph)
	if err != nil {
		return nil, err
	}
	ephPub, err := ecdh.X25519().NewPublicKey(eph)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	kek, err := recoveryKEK(shared)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(kek)
	gcm, _ := cipher.NewGCM(block)
	nonce, err1 := base64.StdEncoding.DecodeString(b.Nonce)
	sealed, err2 := base64.StdEncoding.DecodeString(b.Sealed)
	if err1 != nil || err2 != nil || len(nonce) != gcm.NonceSize() {
		return nil, errors.New("the recovery file is damaged")
	}
	key, err := gcm.Open(nil, nonce, sealed, priv.PublicKey().Bytes())
	if err != nil {
		return nil, errors.New("this recovery key does not open the recovery file")
	}
	return key, nil
}

func readRecoveryFile() (recoveryBlob, error) {
	var b recoveryBlob
	raw, err := os.ReadFile(recoveryFile)
	if err != nil {
		return b, err
	}
	return b, json.Unmarshal(raw, &b)
}

func writeRecoveryFile(b recoveryBlob) error {
	raw, _ := json.MarshalIndent(b, "", "  ")
	return writeSecretFileAtomic(recoveryFile, raw)
}

// recoveryInfo says whether a recovery key exists and since when.
func recoveryInfo() (bool, time.Time) {
	b, err := readRecoveryFile()
	if err != nil {
		return false, time.Time{}
	}
	return true, b.Created
}

// createRecoveryKey makes a new recovery key (replacing any older one), seals
// the current configuration key to it and returns the key to show. The caller
// must have checked who is asking.
func createRecoveryKey() (string, error) {
	key, _, ok := configCrypto()
	if !ok {
		return "", errors.New("the configuration is locked")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	blob, err := sealToRecovery(priv.PublicKey(), key)
	if err != nil {
		return "", err
	}
	blob.Created = time.Now().UTC().Truncate(time.Second)
	if err := writeRecoveryFile(blob); err != nil {
		return "", err
	}
	return formatRecoveryKey(priv.Bytes()), nil
}

// healRecovery re-seals the configuration key when the recovery file holds an
// older one (a crash between the two writes of a password change).
func healRecovery() {
	key, _, ok := configCrypto()
	if !ok {
		return
	}
	b, err := readRecoveryFile()
	if err != nil {
		return
	}
	fp := sha256.Sum256(key)
	if b.Check == base64.StdEncoding.EncodeToString(fp[:8]) {
		return
	}
	if err := resealRecovery(key); err != nil {
		log.Printf("WARNING: the recovery file is out of date and could not be updated: %v", err)
		return
	}
	log.Printf("The recovery file was out of date and has been updated")
}

// removeRecoveryKey deletes the recovery file: the recovery key stops working.
func removeRecoveryKey() error {
	if err := os.Remove(recoveryFile); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// resealRecovery keeps the recovery file in step with a new configuration key.
func resealRecovery(newKey []byte) error {
	b, err := readRecoveryFile()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(b.Pub)
	if err != nil {
		return err
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return err
	}
	nb, err := sealToRecovery(pub, newKey)
	if err != nil {
		return err
	}
	nb.Created = b.Created
	return writeRecoveryFile(nb)
}

// unlockConfigWithRecoveryKey opens the configuration with the recovery key.
// The session is then "recovered": the password is unknown, so setting a new
// one does not ask for the old one.
func unlockConfigWithRecoveryKey(data []byte, text string) ([]byte, error) {
	privBytes, err := parseRecoveryKey(text)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, errors.New("this is not a recovery key")
	}
	blob, err := readRecoveryFile()
	if err != nil {
		return nil, errors.New("there is no recovery file next to the configuration")
	}
	key, err := openRecovery(blob, priv)
	if err != nil {
		return nil, err
	}
	plain, err := decryptWithKey(key, data)
	if err != nil {
		return nil, errors.New("the recovery file does not match this configuration")
	}
	salt, err := secretSalt(data)
	if err != nil {
		return nil, err
	}
	setConfigCrypto(key, salt)
	saveKeyToKeychain(key, salt)
	recoveredMu.Lock()
	recoveredSession = true
	recoveredMu.Unlock()
	log.Printf("Configuration unlocked with the recovery key: set a new master password")
	return plain, nil
}

func isRecoveredSession() bool {
	recoveredMu.Lock()
	defer recoveredMu.Unlock()
	return recoveredSession
}

// verifyMasterPassword checks a password against the key in use, without
// touching the files.
func verifyMasterPassword(password string) bool {
	key, salt, ok := configCrypto()
	if !ok {
		return false
	}
	derived, err := deriveSecretKey(password, salt)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(derived, key) == 1
}

var errPasswordTooShort = fmt.Errorf("the master password must be at least %d characters", minPasswordLen)

// changeMasterPassword re-encrypts the configuration under a new password. The
// old password is required, except in a session unlocked with the recovery key.
func changeMasterPassword(oldPassword, newPassword string) error {
	if len(newPassword) < minPasswordLen {
		return errPasswordTooShort
	}
	if !isRecoveredSession() && !verifyMasterPassword(oldPassword) {
		return errWrongPassword
	}
	oldKey, oldSalt, ok := configCrypto()
	if !ok {
		return errors.New("the configuration is locked")
	}
	salt, err := newSecretSalt()
	if err != nil {
		return err
	}
	key, err := deriveSecretKey(newPassword, salt)
	if err != nil {
		return err
	}
	configMu.Lock()
	defer configMu.Unlock()
	data, err := yaml.Marshal(configuration)
	if err != nil {
		return err
	}
	enc, err := encryptWithKey(key, salt, data)
	if err != nil {
		return err
	}
	if _, err := decryptWithKey(key, enc); err != nil {
		return fmt.Errorf("verifying the encrypted file: %w", err)
	}
	// The configuration goes first. If the process dies before the recovery
	// file follows, healRecovery notices at the next start (the file records a
	// fingerprint of the key it holds) and seals the new key again.
	if err := writeSecretFileAtomic(encryptedConfig, enc); err != nil {
		return err
	}
	if err := resealRecovery(key); err != nil {
		// The configuration is already under the new password; say that the
		// recovery file is out of date so the user makes a new key.
		log.Printf("WARNING: the recovery file could not be updated (%v): create a new recovery key", err)
	}
	keychainDelete(keychainService, keychainAccount(oldSalt))
	setConfigCrypto(key, salt)
	saveKeyToKeychain(key, salt)
	for i := range oldKey {
		oldKey[i] = 0
	}
	recoveredMu.Lock()
	recoveredSession = false
	recoveredMu.Unlock()
	log.Printf("Master password changed")
	return nil
}
