//go:build darwin

package main

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework Foundation -framework LocalAuthentication
#include <stdlib.h>
#include "keychain_darwin.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

const errSecItemNotFound = -25300

func keychainAvailable() bool { return true }

func keychainExists(service, account string) bool {
	cService := C.CString(service)
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	return int(C.kc_exists(cService, cAccount)) == 0
}

func keychainLoad(service, account string) (string, error) {
	cService := C.CString(service)
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))

	var out *C.char
	status := int(C.kc_get(cService, cAccount, &out))
	if status == 0 {
		if out == nil {
			return "", errKeychainNotFound
		}
		defer C.kc_free(out)
		return C.GoString(out), nil
	}
	if status == errSecItemNotFound {
		return "", errKeychainNotFound
	}
	return "", fmt.Errorf("keychain read failed (status %d)", status)
}

func keychainStore(service, account, secret string) error {
	cService := C.CString(service)
	cAccount := C.CString(account)
	cSecret := C.CString(secret)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	defer C.free(unsafe.Pointer(cSecret))

	if status := int(C.kc_set(cService, cAccount, cSecret)); status != 0 {
		return fmt.Errorf("keychain write failed (status %d)", status)
	}
	return nil
}

func keychainDelete(service, account string) error {
	cService := C.CString(service)
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))

	status := int(C.kc_delete(cService, cAccount))
	if status == 0 || status == errSecItemNotFound {
		return nil
	}
	return fmt.Errorf("keychain delete failed (status %d)", status)
}

func biometricAuth(reason string) error {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	switch int(C.kc_biometric_auth(cReason)) {
	case 0:
		return nil
	case 1:
		return errors.New("biometric authentication not available on this device")
	default:
		return errors.New("biometric authentication cancelled")
	}
}
