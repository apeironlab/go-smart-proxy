//go:build !darwin

package main

func keychainAvailable() bool { return false }

func keychainExists(service, account string) bool { return false }

func keychainLoad(service, account string) (string, error) {
	return "", errKeychainUnsupported
}

func keychainStore(service, account, secret string) error {
	return errKeychainUnsupported
}

func keychainDelete(service, account string) error { return nil }

func biometricAuth(reason string) error {
	return errKeychainUnsupported
}
