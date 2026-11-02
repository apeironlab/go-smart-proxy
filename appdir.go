package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const appHomeEnv = "PROXY_HOME"

// prepareWorkingDirectory makes the configuration, relay state and cache land
// in a writable directory also when the binary is launched by a desktop
// environment. Portable runs from a writable directory keep using it; app
// bundles and installed Linux binaries use the user configuration directory.
func prepareWorkingDirectory() {
	if dir := os.Getenv(appHomeEnv); dir != "" {
		if err := useDirectory(dir); err != nil {
			log.Printf("WARNING: cannot use %s=%q: %v", appHomeEnv, dir, err)
		}
		return
	}
	if installedApp() || !writableDir(".") {
		useUserConfigDir()
	}
}

// installedApp reports whether the binary is running from a macOS app bundle or
// from the Linux package installation prefix. In both cases the working
// directory is not a reliable data location.
func installedApp() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	switch runtime.GOOS {
	case "darwin":
		return strings.Contains(exe, ".app/Contents/MacOS/")
	case "linux":
		return strings.HasPrefix(exe, "/usr/")
	default:
		return false
	}
}

func useUserConfigDir() {
	base, err := os.UserConfigDir()
	if err != nil {
		log.Printf("WARNING: cannot determine the user configuration directory: %v", err)
		return
	}
	dir := filepath.Join(base, "go-smart-proxy")
	if err := useDirectory(dir); err != nil {
		log.Printf("WARNING: cannot use data directory %s: %v", dir, err)
	}
}

func useDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chdir(dir); err != nil {
		return err
	}
	log.Printf("Using data directory %s", dir)
	return nil
}

func writableDir(dir string) bool {
	f, err := os.CreateTemp(dir, ".gsp-write-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}
