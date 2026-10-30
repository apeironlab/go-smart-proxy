//go:build !darwin

package main

func applySystemProxy() {}

func systemProxyState() systemProxyStateJSON {
	return systemProxyStateJSON{Exceptions: []string{}}
}
