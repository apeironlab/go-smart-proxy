package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func startEcho(t *testing.T) (host, port string) {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	host, port, _ = net.SplitHostPort(echo.Addr().String())
	return
}

// transparentPair returns the two ends of a connection: the one handleTransparent
// serves and the one the "client" uses.
func transparentPair(t *testing.T) (client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	served := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		served <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	go handleTransparent(<-served)
	return client
}

func withLookup(t *testing.T, f func(string) (string, string, error)) {
	t.Helper()
	old := originalDstLookup
	originalDstLookup = f
	t.Cleanup(func() { originalDstLookup = old })
}

func echoRoundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("no echo of %q: %v", msg, err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
}

func TestTransparentWithTheDestinationOfTheHelper(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	host, port := startEcho(t)
	withLookup(t, func(string) (string, string, error) { return host, port, nil })

	// a protocol where the server speaks first: nothing to read, the address is used
	echoRoundTrip(t, transparentPair(t), "SSH-2.0-test\r\n")
	// the client speaks first and it is HTTP: the name replaces the address and
	// the bytes read to find it still reach the destination
	echoRoundTrip(t, transparentPair(t), "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
}

func TestTransparentWithoutTheHelperReadsTheDestination(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	host, port := startEcho(t)
	withLookup(t, func(string) (string, string, error) { return "", "", errors.New("no helper") })

	echoRoundTrip(t, transparentPair(t), "GET / HTTP/1.1\r\nHost: "+host+":"+port+"\r\n\r\n")

	// nothing to recognise: the connection is closed
	c := transparentPair(t)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "\x00\x01binary garbage\r\n\r\n")
	if _, err := bufio.NewReader(c).ReadByte(); err == nil {
		t.Fatal("an unrecognised connection must be closed")
	}
}

func TestTransparentListenerFollowsTheConfiguration(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	old := transparentListenAddr
	transparentListenAddr = addr
	defer func() { transparentListenAddr = old }()

	var ln net.Listener
	if ln = transparentStep(ln); ln != nil {
		t.Fatal("listening while the option is off")
	}
	configuration.TransparentRoute = []string{"pulse"}
	if ln = transparentStep(ln); ln == nil {
		t.Fatal("not listening while the option is on")
	}
	if c, err := net.DialTimeout("tcp", addr, time.Second); err != nil {
		t.Fatal(err)
	} else {
		c.Close()
	}
	if again := transparentStep(ln); again != ln {
		t.Fatal("the listener must be kept")
	}
	// the address is taken: the step reports nothing open and tries again later
	configuration.TransparentRoute = []string{"pulse"}
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	transparentListenAddr = busy.Addr().String()
	ln.Close()
	if transparentStep(nil) != nil {
		t.Fatal("listening on a busy address")
	}
	transparentListenAddr = addr
	configuration.TransparentRoute = nil
	if transparentStep(ln) != nil {
		t.Fatal("still listening after the option was turned off")
	}
	_ = strconv.Itoa
}
