package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareWorkingDirectoryUsesProxyHome(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })

	dir := t.TempDir()
	t.Setenv("PROXY_HOME", dir)
	prepareWorkingDirectory()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(dir)
	got, _ := filepath.EvalSymlinks(wd)
	if got != want {
		t.Fatalf("working directory = %q, want %q", got, want)
	}
}

func TestWritableDir(t *testing.T) {
	if !writableDir(t.TempDir()) {
		t.Fatal("a temporary directory must be writable")
	}
	if writableDir(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("a missing directory cannot be writable")
	}
}

func TestMigrateDataDirectory(t *testing.T) {
	from := t.TempDir()
	to := t.TempDir()
	if err := os.WriteFile(filepath.Join(from, encryptedConfig), []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(from, "relay_state.json"), []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}

	migrateDataDirectory(from, to)

	if _, err := os.Stat(filepath.Join(to, encryptedConfig)); err != nil {
		t.Fatalf("encrypted configuration was not moved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(to, "relay_state.json")); err != nil {
		t.Fatalf("relay state was not moved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(from, encryptedConfig)); !os.IsNotExist(err) {
		t.Fatal("the source configuration was not removed")
	}
}

func TestMigrateDataDirectoryDoesNotOverwrite(t *testing.T) {
	from := t.TempDir()
	to := t.TempDir()
	if err := os.WriteFile(filepath.Join(from, encryptedConfig), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, encryptedConfig), []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}

	migrateDataDirectory(from, to)

	data, err := os.ReadFile(filepath.Join(to, encryptedConfig))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "current" {
		t.Fatalf("the destination configuration was overwritten: %q", data)
	}
}
