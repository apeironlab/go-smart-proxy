package main

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	notifyMu   sync.Mutex
	lastNotify time.Time
)

// notifyDesktop shows a best-effort desktop notification. Rapid notifications
// are throttled so a burst of requests cannot flood the desktop.
func notifyDesktop(title, body string) {
	if testing.Testing() {
		return // tests must never pop up real notifications
	}
	notifyMu.Lock()
	if time.Since(lastNotify) < 1500*time.Millisecond {
		notifyMu.Unlock()
		return
	}
	lastNotify = time.Now()
	notifyMu.Unlock()

	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(`display notification "%s" with title "%s"`,
			escapeAppleScript(body), escapeAppleScript(title))
		if err := exec.Command("osascript", "-e", script).Run(); err != nil {
			log.Printf("desktop notification: %v", err)
		}
	case "linux":
		if err := exec.Command("notify-send", title, body).Run(); err != nil {
			log.Printf("desktop notification: %v", err)
		}
	case "windows":
		notifyWindows(title, body)
	}
}

func escapeAppleScript(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
