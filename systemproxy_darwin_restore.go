//go:build darwin

package main

// restoreSystemProxy: on macOS the settings the proxy writes stay in place
// (they are the user's choice to keep proxying, and are applied again at each
// start).
func restoreSystemProxy() {}
