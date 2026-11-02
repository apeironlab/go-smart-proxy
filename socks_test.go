package main

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// socksCONNECT performs the SOCKS5 handshake with a local proxy and returns
// the established tunnel.
func socksCONNECT(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()

	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(br, reply); err != nil {
		c.Close()
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		c.Close()
		t.Fatalf("method negotiation failed: %v", reply)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(append(req, 0x01), ip4...)
		} else {
			req = append(append(req, 0x04), ip.To16()...)
		}
	} else {
		req = append(append(req, 0x03, byte(len(host))), host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		t.Fatal(err)
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(br, resp); err != nil {
		c.Close()
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		c.Close()
		t.Fatalf("CONNECT failed: %v", resp)
	}
	var skip int
	switch resp[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		n, err := br.ReadByte()
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		skip = int(n) + 2
	default:
		c.Close()
		t.Fatalf("bad address type in reply: %v", resp)
	}
	if _, err := io.CopyN(io.Discard, br, int64(skip)); err != nil {
		c.Close()
		t.Fatal(err)
	}
	c.SetDeadline(time.Time{})
	// br may hold bytes read ahead: expose it through the connection.
	return &bufConn{Conn: c, br: br}
}

func TestSOCKS5CONNECT(t *testing.T) {
	resetEnv(t, nil, []ConfigRoute{{Name: "Direct"}})

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

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSOCKS(c)
		}
	}()

	conn := socksCONNECT(t, ln.Addr().String(), echo.Addr().String())
	defer conn.Close()

	if _, err := io.WriteString(conn, "hello over socks"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("hello over socks"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello over socks" {
		t.Fatalf("got %q", buf)
	}
}
