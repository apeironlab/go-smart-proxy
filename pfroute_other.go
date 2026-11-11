//go:build !darwin

package main

func transparentStatus() transparentStatusJSON {
	return transparentStatusJSON{Configured: []string{}, Interfaces: []string{}}
}

func applyTransparentRouting()  {}
func removeTransparentRouting() {}
