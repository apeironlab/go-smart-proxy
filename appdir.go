package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	appHomeEnv      = "PROXY_HOME"
	installedMarker = "installed.marker"
)

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

// installedApp reports whether the binary is running from a macOS app bundle,
// a Windows installer installation, or the Linux package installation prefix.
// In all these cases the working directory is not a reliable data location.
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
	case "windows":
		// The Inno Setup installer writes this marker next to proxy.exe;
		// portable zip archives do not contain it.
		_, err := os.Stat(filepath.Join(filepath.Dir(exe), installedMarker))
		return err == nil
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
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("WARNING: cannot create data directory %s: %v", dir, err)
		return
	}
	// The previous data may be next to the executable (installed Windows app)
	// or in the process working directory (shortcut vs auto-start).
	for _, candidate := range dataDirCandidates() {
		if abs, err := filepath.Abs(candidate); err == nil && abs != dir {
			migrateDataDirectory(abs, dir)
		}
	}
	if err := useDirectory(dir); err != nil {
		log.Printf("WARNING: cannot use data directory %s: %v", dir, err)
	}
}

func dataDirCandidates() []string {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	return candidates
}

// migrateDataDirectory moves the files that identify an installation from a
// previous working directory (for example the Windows program folder) to the
// user configuration directory. It never overwrites a configuration that
// already exists in the destination.
func migrateDataDirectory(from, to string) {
	if from == to {
		return
	}
	if fileExists(filepath.Join(to, encryptedConfig)) || fileExists(filepath.Join(to, plainConfig)) {
		return
	}
	moved := false
	for _, name := range []string{encryptedConfig, plainConfig, configKeyFile, "relay_state.json"} {
		src := filepath.Join(from, name)
		if !fileExists(src) {
			continue
		}
		dst := filepath.Join(to, name)
		if fileExists(dst) {
			continue
		}
		if err := moveFile(src, dst); err != nil {
			log.Printf("WARNING: cannot move %s to %s: %v", src, dst, err)
			continue
		}
		moved = true
	}
	if moved {
		log.Printf("Moved the existing data from %s to %s", from, to)
	}
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		return err
	}
	return os.Remove(src)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
