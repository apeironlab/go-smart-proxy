package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRelayClientLoadFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "state.json")
	c := &relayClient{file: file, approvals: map[int64]*relayApproval{}}
	c.loadFile() // nothing saved yet
	os.WriteFile(file, []byte("{"), 0o600)
	c.loadFile() // not JSON: ignored

	saved := relayPersisted{NextID: 7, Rules: []relayRule{{ID: 3, From: "a@example.org", Host: "x.example", Port: 443}}}
	saved.State.Contacts = nil
	b, _ := json.Marshal(saved)
	os.WriteFile(file, b, 0o600)
	c.loadFile()
	if c.nextID != 7 || len(c.rules) != 1 || c.rules[0].FromDevice != "default" {
		t.Errorf("loaded: nextID=%d rules=%+v", c.nextID, c.rules)
	}
	c.RemoveRule(3)
	c.RemoveRule(99)
	if len(c.rules) != 0 {
		t.Errorf("rules after removal: %+v", c.rules)
	}
	if b, _ := os.ReadFile(file); !json.Valid(b) {
		t.Error("the rules were not saved")
	}
	c.SetDevice("k7m2p9qx")
	if c.device != "k7m2p9qx" {
		t.Error("device not set")
	}
}

func TestRelayClientGuard(t *testing.T) {
	c := &relayClient{cfg: &RelayConfig{}}
	for _, addr := range []string{"127.0.0.1:80", "[::1]:80", "0.0.0.0:80", "169.254.1.1:80", "224.0.0.1:80", "example.org:80", "nonsense"} {
		if c.guard("tcp", addr, nil) == nil {
			t.Errorf("%s was allowed", addr)
		}
	}
	if err := c.guard("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("a public address was refused: %v", err)
	}
	c.cfg.AllowLocal = true
	if err := c.guard("tcp", "127.0.0.1:80", nil); err != nil {
		t.Errorf("AllowLocal ignored: %v", err)
	}
	if deviceSuffix("") != "" || deviceSuffix("abc") != "/abc" {
		t.Error("deviceSuffix")
	}
}

func TestServeSOCKSListenerFollowsConfiguration(t *testing.T) {
	// serveSOCKS runs until told to stop.
	socksStopped.Store(false)
	t.Cleanup(func() {
		socksStopped.Store(true)
		restartSocksListener()
		time.Sleep(100 * time.Millisecond)
	})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	configMu.Lock()
	configuration.SocksAddress = addr
	configMu.Unlock()
	go serveSOCKS()

	deadline := time.Now().Add(5 * time.Second)
	var conn net.Conn
	for time.Now().Before(deadline) {
		var err error
		if conn, err = net.DialTimeout("tcp", addr, time.Second); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("the SOCKS listener did not start")
	}
	// A client that speaks nonsense is dropped.
	conn.Write([]byte{0x04, 0x01, 0x00})
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected the connection to close")
	}
	conn.Close()

	// Closing the listener makes the loop open it again.
	restartSocksListener()
	var c2 net.Conn
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		var err error
		if c2, err = net.DialTimeout("tcp", addr, time.Second); err == nil {
			break
		}
	}
	if c2 == nil {
		t.Fatal("the listener was not reopened")
	}
	c2.Close()
}
