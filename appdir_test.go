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
