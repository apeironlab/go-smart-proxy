//go:build windows

package main

import (
	"log"
	"os"
	"os/exec"
)

// notifyWindows shows a toast notification through PowerShell.
func notifyWindows(title, body string) {
	name, args, env := windowsToastCommand(title, body)
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	hideWindow(cmd)
	if err := cmd.Run(); err != nil {
		log.Printf("desktop notification: %v", err)
	}
}
