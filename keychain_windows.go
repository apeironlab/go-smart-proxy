//go:build windows

package main

import (
	"encoding/hex"
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows has no Keychain equivalent: the derived configuration key is stored
// in a file protected with DPAPI (CryptProtectData). DPAPI ties it to the
// current Windows user, so copying the encrypted configuration to another
// machine still requires the master password, while normal restarts on the
// same profile unlock silently.

func keychainAvailable() bool { return true }

func keychainExists(service, account string) bool {
	_, err := os.Stat(configKeyFile)
	return err == nil
}

func keychainLoad(service, account string) (string, error) {
	data, err := os.ReadFile(configKeyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", errKeychainNotFound
		}
		return "", err
	}
	key, err := dpapiUnprotect(data)
	if err != nil {
		return "", err
	}
	if len(key) != secretKeySize {
		return "", errors.New("invalid key length in the DPAPI store")
	}
	return hex.EncodeToString(key), nil
}

func keychainStore(service, account, secret string) error {
	key, err := hex.DecodeString(secret)
	if err != nil || len(key) != secretKeySize {
		return errors.New("invalid configuration key")
	}
	protected, err := dpapiProtect(key)
	if err != nil {
		return err
	}
	return writeSecretFileAtomic(configKeyFile, protected)
}

func keychainDelete(service, account string) error {
	err := os.Remove(configKeyFile)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}

// DPAPI already authenticates the current Windows user; no extra prompt is
// needed (or possible without a GUI dependency).
func biometricAuth(reason string) error { return nil }

func dpapiProtect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot protect empty data")
	}
	in := &windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	buf := make([]byte, out.Size)
	copy(buf, unsafe.Slice(out.Data, out.Size))
	return buf, nil
}

func dpapiUnprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty DPAPI data")
	}
	in := &windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	buf := make([]byte, out.Size)
	copy(buf, unsafe.Slice(out.Data, out.Size))
	return buf, nil
}
