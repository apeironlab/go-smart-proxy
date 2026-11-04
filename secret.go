package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/term"

	"proxy/relay"
)

const (
	secretMagic     = "GSP1"
	secretSaltSize  = 16
	secretNonceSize = 12
	secretKeySize   = 32
	secretEnv       = "PROXY_MASTER_PASSWORD"
	noKeychainEnv   = "PROXY_NO_KEYCHAIN"
	encryptedConfig = "config.yml.enc"
	plainConfig     = "config.yml"
	configKeyFile   = "config.key.dpapi"
	minPasswordLen  = 8
	keychainService = "go-smart-proxy"
)

// secretIterations is the PBKDF2 work factor (a variable so that tests can lower it).
var secretIterations = 600_000

var (
	secretMu   sync.Mutex
	configKey  []byte
	configSalt []byte

	errKeychainNotFound    = errors.New("keychain item not found")
	errKeychainUnsupported = errors.New("keychain not supported")
)

// deriveSecretKey derives the AES key from the master password and the salt
// stored in the configuration file.
func deriveSecretKey(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, secretIterations, secretKeySize)
}

// newSecretSalt returns a fresh random salt.
func newSecretSalt() ([]byte, error) {
	salt := make([]byte, secretSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// encryptWithKey encrypts plaintext with an already derived key. The output is:
// magic (4) | salt (16) | nonce (12) | ciphertext.
func encryptWithKey(key, salt, plaintext []byte) ([]byte, error) {
	if len(key) != secretKeySize || len(salt) != secretSaltSize {
		return nil, errors.New("invalid encryption key or salt")
	}
	nonce := make([]byte, secretNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(secretMagic)+secretSaltSize+secretNonceSize+len(plaintext)+gcm.Overhead())
	out = append(out, secretMagic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// secretSalt extracts the KDF salt from an encrypted file.
func secretSalt(data []byte) ([]byte, error) {
	head := len(secretMagic) + secretSaltSize + secretNonceSize
	if len(data) < head || string(data[:len(secretMagic)]) != secretMagic {
		return nil, errors.New("not an encrypted file (bad header)")
	}
	return append([]byte(nil), data[len(secretMagic):len(secretMagic)+secretSaltSize]...), nil
}

func decryptWithKey(key, data []byte) ([]byte, error) {
	head := len(secretMagic) + secretSaltSize + secretNonceSize
	if len(data) < head || string(data[:len(secretMagic)]) != secretMagic {
		return nil, errors.New("not an encrypted file (bad header)")
	}
	nonce := data[len(secretMagic)+secretSaltSize : head]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, data[head:], nil)
	if err != nil {
		return nil, errors.New("wrong master password or corrupted file")
	}
	return plain, nil
}

// encryptSecret encrypts with a fresh salt derived from password. Used by tests
// and by callers that create a brand-new encrypted file.
func encryptSecret(password string, plaintext []byte) ([]byte, error) {
	salt, err := newSecretSalt()
	if err != nil {
		return nil, err
	}
	key, err := deriveSecretKey(password, salt)
	if err != nil {
		return nil, err
	}
	return encryptWithKey(key, salt, plaintext)
}

func decryptSecret(password string, data []byte) ([]byte, error) {
	salt, err := secretSalt(data)
	if err != nil {
		return nil, err
	}
	key, err := deriveSecretKey(password, salt)
	if err != nil {
		return nil, err
	}
	return decryptWithKey(key, data)
}

// writeSecretFileAtomic writes data to path with owner-only permissions, via an
// exclusively created temporary file next to it.
func writeSecretFileAtomic(path string, data []byte) error {
	return relay.WriteFileAtomic(path, data, 0o600)
}

// setConfigCrypto caches the key and salt used for the current configuration.
// The key is what the app uses from now on: the master password is no longer
// kept in memory.
func setConfigCrypto(key, salt []byte) {
	// Whoever unlocks with the password is not in a "recovered" session; the
	// recovery path sets that flag after calling this.
	recoveredMu.Lock()
	recoveredSession = false
	recoveredMu.Unlock()
	secretMu.Lock()
	configKey = append([]byte(nil), key...)
	configSalt = append([]byte(nil), salt...)
	secretMu.Unlock()
}

func configCrypto() (key, salt []byte, ok bool) {
	secretMu.Lock()
	defer secretMu.Unlock()
	if len(configKey) == 0 {
		return nil, nil, false
	}
	return append([]byte(nil), configKey...), append([]byte(nil), configSalt...), true
}

func clearConfigCrypto() {
	secretMu.Lock()
	configKey, configSalt = nil, nil
	secretMu.Unlock()
}

var (
	errConfigLocked  = errors.New("the configuration is locked: the master password is required")
	errWrongPassword = errors.New("wrong master password")
)

// hasTerminal reports whether a password can be read interactively.
func hasTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// unlockConfigStored tries to unlock data without asking the user: it uses the
// master password from the environment or the key stored in the system key
// store (Keychain on macOS, DPAPI on Windows). It returns errConfigLocked when
// neither source is available.
func unlockConfigStored(data []byte) ([]byte, error) {
	salt, err := secretSalt(data)
	if err != nil {
		return nil, err
	}

	if p := os.Getenv(secretEnv); p != "" {
		key, err := deriveSecretKey(p, salt)
		if err != nil {
			return nil, err
		}
		plain, err := decryptWithKey(key, data)
		if err != nil {
			return nil, fmt.Errorf("wrong master password in %s", secretEnv)
		}
		setConfigCrypto(key, salt)
		// The password came from the environment once: remember the derived
		// key so the next GUI launch does not need it again.
		saveKeyToKeychain(key, salt)
		return plain, nil
	}

	if keychainEnabled() {
		account := keychainAccount(salt)
		if keychainExists(keychainService, account) {
			if err := biometricAuth("Unlock the Go Smart Proxy configuration"); err == nil {
				if encoded, err := keychainLoad(keychainService, account); err == nil {
					if key, err := hex.DecodeString(encoded); err == nil && len(key) == secretKeySize {
						if plain, err := decryptWithKey(key, data); err == nil {
							setConfigCrypto(key, salt)
							return plain, nil
						}
					}
				}
				log.Printf("Key stored in the system keychain is not valid for this configuration, removing it")
				keychainDelete(keychainService, account)
			} else {
				log.Printf("Keychain unlock not available: %v (the master password is required)", err)
			}
		}
	}

	return nil, errConfigLocked
}

// unlockConfigWithPassword decrypts data with an explicitly supplied master
// password and remembers the derived key in the system key store.
func unlockConfigWithPassword(data []byte, password string) ([]byte, error) {
	// A recovery key can be typed where the password is asked.
	if looksLikeRecoveryKey(password) {
		return unlockConfigWithRecoveryKey(data, password)
	}
	salt, err := secretSalt(data)
	if err != nil {
		return nil, err
	}
	key, err := deriveSecretKey(password, salt)
	if err != nil {
		return nil, err
	}
	plain, err := decryptWithKey(key, data)
	if err != nil {
		return nil, errWrongPassword
	}
	setConfigCrypto(key, salt)
	saveKeyToKeychain(key, salt)
	return plain, nil
}

// unlockConfigInteractive unlocks data using the stored key or, when that is
// not available, asks for the master password three times in the terminal.
func unlockConfigInteractive(data []byte) ([]byte, error) {
	plain, err := unlockConfigStored(data)
	if err == nil {
		return plain, nil
	}
	if !errors.Is(err, errConfigLocked) {
		return nil, err
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		password, err := promptPassword("Master password")
		if err != nil {
			return nil, err
		}
		plain, err := unlockConfigWithPassword(data, password)
		if err == nil {
			return plain, nil
		}
		lastErr = err
		log.Printf("Master password not valid, retry (%d/3)", attempt+1)
	}
	if lastErr == nil {
		lastErr = errors.New("no password provided")
	}
	return nil, lastErr
}

// newMasterPassword obtains and confirms a new master password (used by the
// automatic migration of a plaintext configuration).
func newMasterPassword() (string, error) {
	if p := os.Getenv(secretEnv); p != "" {
		if len(p) < minPasswordLen {
			return "", fmt.Errorf("%s must be at least %d characters", secretEnv, minPasswordLen)
		}
		return p, nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		p, err := promptPassword(fmt.Sprintf("New master password (min %d characters)", minPasswordLen))
		if err != nil {
			return "", err
		}
		if len(p) < minPasswordLen {
			log.Printf("Master password must be at least %d characters", minPasswordLen)
			continue
		}
		again, err := promptPassword("Repeat master password")
		if err != nil {
			return "", err
		}
		if p != again {
			log.Printf("Passwords do not match")
			continue
		}
		return p, nil
	}
	return "", errors.New("cannot set the master password")
}

func keychainEnabled() bool {
	if os.Getenv(noKeychainEnv) != "" {
		return false
	}
	return keychainAvailable()
}

func keychainAccount(salt []byte) string {
	h := sha256.Sum256(salt)
	return "config-key-" + hex.EncodeToString(h[:8])
}

func saveKeyToKeychain(key, salt []byte) {
	if !keychainEnabled() {
		return
	}
	account := keychainAccount(salt)
	if err := keychainStore(keychainService, account, hex.EncodeToString(key)); err != nil {
		log.Printf("Keychain: cannot store the configuration key: %v", err)
		return
	}
	log.Printf("Configuration key stored in the system keychain (biometric unlock when available)")
}

func promptPassword(label string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, label+": ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return promptPasswordGUI(label)
}

// promptPasswordGUI asks for the password without a terminal (e.g. when the
// app is started from Finder/launchd).
func promptPasswordGUI(label string) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(`set d to display dialog "%s" default answer "" with hidden answer buttons {"OK"} default button 1 with title "Go Smart Proxy"
return text returned of d`, strings.ReplaceAll(label, `"`, `'`))
		out, err := exec.Command("osascript", "-e", script).Output()
		if err != nil {
			return "", errors.New("master password required: set " + secretEnv + " or start the proxy from a terminal")
		}
		return strings.TrimRight(string(out), "\r\n"), nil
	case "linux":
		out, err := exec.Command("zenity", "--password", "--title=Go Smart Proxy", "--text="+label).Output()
		if err != nil {
			return "", errors.New("master password required: set " + secretEnv + " or start the proxy from a terminal")
		}
		return strings.TrimRight(string(out), "\r\n"), nil
	default:
		return "", errors.New("master password required: set " + secretEnv)
	}
}
