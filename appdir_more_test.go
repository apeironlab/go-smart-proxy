package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUseUserConfigDirMovesTheOldData(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home) // where os.UserConfigDir looks on Linux
	t.Setenv("HOME", home)
	t.Setenv("AppData", home) // ... and on Windows
	work := t.TempDir()
	t.Chdir(work)
	os.WriteFile(filepath.Join(work, encryptedConfig), []byte("enc"), 0o600)
	os.WriteFile(filepath.Join(work, "relay_state.json"), []byte("st"), 0o600)

	useUserConfigDir()

	base, err := os.UserConfigDir() // Library/Application Support on macOS
	if err != nil {
		t.Skip(err)
	}
	dir := filepath.Join(base, "go-smart-proxy")
	for _, name := range []string{encryptedConfig, "relay_state.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was not carried over: %v", name, err)
		}
	}
	if wd, _ := os.Getwd(); filepath.Base(wd) != "go-smart-proxy" {
		t.Errorf("working directory = %s", wd)
	}
	if len(dataDirCandidates()) == 0 {
		t.Error("no candidate directories")
	}
}

func TestMigrationNeverOverwritesAnExistingConfiguration(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(from, encryptedConfig), []byte("old"), 0o600)
	os.WriteFile(filepath.Join(to, encryptedConfig), []byte("new"), 0o600)
	migrateDataDirectory(from, to)
	if b, _ := os.ReadFile(filepath.Join(to, encryptedConfig)); string(b) != "new" {
		t.Errorf("the destination was overwritten: %q", b)
	}
	migrateDataDirectory(from, from) // nothing to do

	// a file already present at the destination is kept, the others move
	from2, to2 := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(from2, plainConfig), []byte("plain"), 0o600)
	os.WriteFile(filepath.Join(from2, "relay_state.json"), []byte("new state"), 0o600)
	os.WriteFile(filepath.Join(to2, "relay_state.json"), []byte("kept"), 0o600)
	migrateDataDirectory(from2, to2)
	if b, _ := os.ReadFile(filepath.Join(to2, "relay_state.json")); string(b) != "kept" {
		t.Errorf("state = %q", b)
	}
	if _, err := os.Stat(filepath.Join(to2, plainConfig)); err != nil {
		t.Error("the plain configuration was not moved")
	}
}

func TestMoveFileAcrossAndMissing(t *testing.T) {
	d := t.TempDir()
	src := filepath.Join(d, "a")
	os.WriteFile(src, []byte("x"), 0o644)
	if err := moveFile(src, filepath.Join(d, "b")); err != nil {
		t.Fatal(err)
	}
	if err := moveFile(filepath.Join(d, "missing"), filepath.Join(d, "c")); err == nil {
		t.Error("moved a missing file")
	}
	if fileExists(src) || !fileExists(filepath.Join(d, "b")) {
		t.Error("the file did not move")
	}
	// a destination that cannot be written
	os.WriteFile(src, []byte("x"), 0o644)
	if err := moveFile(src, filepath.Join(d, "nodir", "x")); err == nil {
		t.Error("wrote into a missing directory")
	}
	t.Setenv("PROXY_HOME", filepath.Join(src, "inside-a-file"))
	prepareWorkingDirectory() // reports and carries on
	_ = installedApp()
}
