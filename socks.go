package main

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	socksListenMu       sync.Mutex
	activeSocksListener net.Listener
)

// serveSOCKS runs the SOCKS5 listener, if configured. Like serve(), it
// re-opens the listener when the configured address changes.
func serveSOCKS() {
	for {
		configMu.Lock()
		addr := configuration.SocksAddress
		configMu.Unlock()

		if addr == "" {
			time.Sleep(2 * time.Second)
			continue
		}

		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("Error listening for SOCKS5 on %s: %+v", addr, err)
			time.Sleep(3 * time.Second)
			continue
		}
		socksListenMu.Lock()
		activeSocksListener = ln
		socksListenMu.Unlock()
		log.Printf("SOCKS5 listening on %s", addr)

		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break // listener replaced
				}
				log.Printf("Error accepting SOCKS5 connection: %+v", err)
				continue
			}
			if !acceptClient(c) {
				c.Close()
				continue
			}
			log.Printf("New SOCKS5 connection from %s", c.RemoteAddr().String())
			activeConns.add(c)
			go handleSOCKS(c)
		}
	}
}

// restartSocksListener closes the current SOCKS listener: the serve loop
// re-opens it with the new address from the configuration (or stops when the
// address becomes empty).
func restartSocksListener() {
	socksListenMu.Lock()
	ln := activeSocksListener
	socksListenMu.Unlock()
	if ln != nil {
		ln.Close()
	}
}

// handleSOCKS speaks SOCKS5 (RFC 1928, no authentication) and connects the
// client through the route selected for the destination.
func handleSOCKS(client net.Conn) {
	rawClient := client
	defer activeConns.remove(rawClient)
	defer rawClient.Close()

	client.SetDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReader(client)

	// Method negotiation: version 5, only "no authentication".
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil || header[0] != 0x05 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		if m == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		client.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// CONNECT request: version, command, reserved, address type.
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // only CONNECT
		socksReply(client, 0x07) // command not supported
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		n, err := br.ReadByte()
		if err != nil {
			return
		}
		b := make([]byte, int(n))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	default:
		socksReply(client, 0x08) // address type not supported
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	client.SetDeadline(time.Time{})

	upstream, upstreamBr, rec, err := dialTarget("socks", client.RemoteAddr().String(), host, strconv.Itoa(port), "SOCKS5", "")
	if err != nil {
		var be *blockedError
		if errors.As(err, &be) {
			socksReply(client, 0x02) // connection not allowed by ruleset
			return
		}
		socksReply(client, 0x01) // general failure
		return
	}
	defer func() {
		if rec.state() != StateFailed {
			rec.finish(StateClosed)
		}
	}()
	rec.setCloseFn(func() {
		client.Close()
		upstream.Close()
	})
	defer func() {
		activeConns.remove(upstream)
		upstream.Close()
	}()

	if _, err := client.Write(socksReplyBytes(0x00)); err != nil {
		return
	}

	cc := &countingConn{Conn: client, in: &rec.bytesClientIn, out: &rec.bytesClientOut}
	tunnel(cc, &countingReader{Reader: br, counter: &rec.bytesClientIn}, upstream, upstreamBr)
}

func socksReply(c net.Conn, code byte) {
	c.Write(socksReplyBytes(code))
}

func socksReplyBytes(code byte) []byte {
	// BND.ADDR/BND.PORT are irrelevant for CONNECT: all zeroes.
	return []byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}
