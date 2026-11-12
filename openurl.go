package main

import (
	"net"
	"os/exec"
	"runtime"
	"testing"
)

// webUIURL returns the address of the management page, as reachable from this machine.
func webUIURL() string {
	host, port, err := net.SplitHostPort(configuration.Address)
	if err != nil {
		return "http://" + configuration.Address + "/"
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/"
}

// openBrowser opens url with the default browser.
func openBrowser(url string) error {
	if testing.Testing() {
		return nil // tests must not open browser windows
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
