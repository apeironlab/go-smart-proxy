//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestProcTableAddresses(t *testing.T) {
	// 127.0.0.1 is written "0100007F" and ::1 "00000000000000000000000001000000"
	if !tableAddrMatches("0100007F", net.ParseIP("127.0.0.1")) {
		t.Error("IPv4")
	}
	if tableAddrMatches("0100007F", net.ParseIP("127.0.0.2")) {
		t.Error("another IPv4 address matched")
	}
	if !tableAddrMatches("00000000000000000000000001000000", net.ParseIP("::1")) {
		t.Error("IPv6")
	}
	if !tableAddrMatches("0000000000000000FFFF00000100007F", net.ParseIP("127.0.0.1")) {
		t.Error("an IPv4 client on an IPv6 socket")
	}
	for _, bad := range []string{"", "zz", "0100", "0100007F00"} {
		if tableAddrMatches(bad, net.ParseIP("127.0.0.1")) {
			t.Errorf("%q matched", bad)
		}
	}
}

func TestScanTCPTable(t *testing.T) {
	table := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D431 0100007F:0C38 01 00000000:00000000 00:00000000 00000000  1000        0 55555 1 0000000000000000 20 4 30 10 -1\n" +
		"   1: 0100007F:0C38 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 66666 1 0000000000000000 20 4 30 10 -1\n" +
		"   garbage line\n"
	p := filepath.Join(t.TempDir(), "tcp")
	os.WriteFile(p, []byte(table), 0o600)
	// port 0xD431 = 54321
	if got := scanTCPTable(p, net.ParseIP("127.0.0.1"), 54321); got != "55555" {
		t.Errorf("inode = %q", got)
	}
	if got := scanTCPTable(p, net.ParseIP("127.0.0.1"), 3128); got != "66666" {
		t.Errorf("inode of the listener side = %q", got)
	}
	if scanTCPTable(p, net.ParseIP("127.0.0.1"), 1) != "" || scanTCPTable(filepath.Join(t.TempDir(), "none"), net.ParseIP("127.0.0.1"), 1) != "" {
		t.Error("something was found where nothing is")
	}
}

func TestParseProcStat(t *testing.T) {
	// the name has spaces and a parenthesis in it
	line := "1234 (my (odd) prog) S 77 1234 1234 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
	ppid, ticks, ok := parseProcStat(line)
	if !ok || ppid != 77 || ticks != 98765 {
		t.Errorf("ppid %d ticks %d ok %v", ppid, ticks, ok)
	}
	for _, bad := range []string{"", "no parenthesis", "1 (a) S 1 2"} {
		if _, _, ok := parseProcStat(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestWindowOfPID(t *testing.T) {
	out := "_NET_WM_PID(CARDINAL) = 4321\n_NET_WM_NAME(UTF8_STRING) = \"README.md - Editor\"\n"
	if title, ok := windowOfPID(out, 4321); !ok || title != "README.md - Editor" {
		t.Errorf("title %q ok %v", title, ok)
	}
	if _, ok := windowOfPID(out, 1); ok {
		t.Error("a window of another program")
	}
	if _, ok := windowOfPID("_NET_WM_PID(CARDINAL) = 1\n", 1); ok {
		t.Error("a window without a title")
	}
}
