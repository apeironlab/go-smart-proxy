package main

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseSNI(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		tls.Client(c1, &tls.Config{ServerName: "www.example.org", InsecureSkipVerify: true}).Handshake()
	}()
	c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16384)
	n, err := c2.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	if got := parseSNI(buf[:n]); got != "www.example.org" {
		t.Fatalf("SNI = %q", got)
	}
	br := bufio.NewReaderSize(strings.NewReader(string(buf[:n])), 16*1024+8)
	h, p, err := sniffDestination(br)
	if err != nil || h != "www.example.org" || p != "443" {
		t.Fatalf("sniff = %q %q %v", h, p, err)
	}
	if br.Buffered() == 0 {
		t.Fatal("sniffing must not consume the bytes")
	}
}

func TestSniffHTTPHost(t *testing.T) {
	for in, want := range map[string]string{
		"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n":   "example.com:80",
		"GET / HTTP/1.1\r\nhost: example.com:8080\r\n\r\n":             "example.com:8080",
		"POST /x HTTP/1.1\r\nUser-Agent: a\r\nHost: [::1]\r\n\r\nbody": "::1:80",
	} {
		br := bufio.NewReaderSize(strings.NewReader(in), 16*1024+8)
		h, p, err := sniffDestination(br)
		got := h + ":" + p
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v want %q", in, got, err, want)
		}
	}
	br := bufio.NewReaderSize(strings.NewReader("GET / HTTP/1.1\r\n\r\n"), 16*1024+8)
	if _, _, err := sniffDestination(br); err == nil {
		t.Error("missing Host must fail")
	}
}

// A short request must be recognised without waiting for more bytes (the
// connection stays open: the client waits for the answer).
func TestSniffHTTPDoesNotWaitForMoreBytes(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go c1.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	done := make(chan string, 1)
	go func() {
		h, p, err := sniffDestination(bufio.NewReaderSize(c2, 16*1024+8))
		if err != nil {
			done <- err.Error()
			return
		}
		done <- h + ":" + p
	}()
	select {
	case got := <-done:
		if got != "example.com:80" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sniffDestination blocks waiting for more bytes")
	}
}
