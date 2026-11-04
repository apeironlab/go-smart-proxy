//go:build !darwin && !windows

package main

func applySystemProxy() {}

func systemProxyState() systemProxyStateJSON {
	return systemProxyStateJSON{Exceptions: []string{}}
}

// restoreSystemProxy has nothing to undo here: the proxy settings of the
// system were never changed (macOS keeps its settings, see systemproxy_darwin.go).
func restoreSystemProxy() {}
