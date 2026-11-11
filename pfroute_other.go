//go:build !darwin

package main

import "errors"

func transparentStatus() transparentStatusJSON {
	return transparentStatusJSON{Configured: []string{}, Interfaces: []string{}}
}

func applyTransparentRouting()  {}
func removeTransparentRouting() {}

// lookupOriginalDst: only macOS redirects connections to the transparent listener.
func lookupOriginalDst(client string) (string, string, error) {
	return "", "", errors.New("not supported")
}

func runPFHelper(args []string) int { return 2 }

func authorizeTransparent() {}
