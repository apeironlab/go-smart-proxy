package main

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// Transparent routing: the packet filter (pfroute_darwin.go) redirects the
// HTTP/HTTPS connections that leave through the selected interfaces to this
// listener, so that applications that ignore the system proxy still go
// through the proxy routes. The destination is read from the traffic itself:
// the SNI of the TLS handshake, or the Host header of a plain HTTP request.
// Connections without either (raw IP, other protocols) are closed.

// transparentAddr is where the packet filter redirects the connections. It
// listens on the loopback only.
const transparentAddr = "127.0.0.1:3129"

// serveTransparent keeps the transparent listener open while at least one
// interface is selected in the configuration.
func serveTransparent() {
	var ln net.Listener
	for {
		configMu.Lock()
		on := len(configuration.TransparentRoute) > 0
		configMu.Unlock()
		switch {
		case on && ln == nil:
			l, err := net.Listen("tcp", transparentAddr)
			if err != nil {
				log.Printf("Error listening for transparent routing on %s: %+v", transparentAddr, err)
			} else {
				ln = l
				log.Printf("Transparent routing listening on %s", transparentAddr)
				go acceptTransparent(l)
			}
		case !on && ln != nil:
			ln.Close()
			ln = nil
		}
		time.Sleep(2 * time.Second)
	}
}

func acceptTransparent(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("Error accepting transparent connection: %+v", err)
			continue
		}
		activeConns.add(c)
		go handleTransparent(c)
	}
}

func handleTransparent(client net.Conn) {
	defer activeConns.remove(client)
	defer client.Close()

	client.SetReadDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(client, 16*1024+8)
	host, port, err := sniffDestination(br)
	client.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("Transparent connection from %s: no destination (%v)", client.RemoteAddr(), err)
		return
	}

	upstream, upstreamBr, rec, err := dialTarget("transparent", client.RemoteAddr().String(), host, port, "TRANSPARENT", "")
	if err != nil {
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

	cc := &countingConn{Conn: client, in: &rec.bytesClientIn, out: &rec.bytesClientOut}
	// The bytes sniffed are still in br: they are forwarded to the upstream.
	tunnel(cc, &countingReader{Reader: br, counter: &rec.bytesClientIn}, upstream, upstreamBr)
}

// sniffDestination returns the destination of a redirected connection
// without consuming the bytes it reads.
func sniffDestination(br *bufio.Reader) (host, port string, err error) {
	first, err := br.Peek(1)
	if err != nil {
		return "", "", err
	}
	if first[0] == 0x16 { // TLS handshake
		hdr, err := br.Peek(5)
		if err != nil {
			return "", "", err
		}
		n := 5 + int(hdr[3])<<8 | int(hdr[4])
		if n > br.Size() {
			n = br.Size()
		}
		data, err := br.Peek(n)
		if err != nil && len(data) < n {
			// Use what arrived: a ClientHello usually fits in the first segment.
			data, _ = br.Peek(br.Buffered())
		}
		name := parseSNI(data)
		if name == "" {
			return "", "", errors.New("TLS without SNI")
		}
		return name, "443", nil
	}
	// Plain HTTP: wait for the end of the headers. Peek(n) blocks until n
	// bytes are there, so ask for one more byte than already buffered.
	for {
		data, _ := br.Peek(br.Buffered())
		if bytes.Contains(data, []byte("\r\n\r\n")) || len(data) >= br.Size() {
			return parseHostHeader(data)
		}
		if _, perr := br.Peek(len(data) + 1); perr != nil {
			data, _ = br.Peek(br.Buffered())
			return parseHostHeader(data)
		}
	}
}

// parseHostHeader extracts host and port from the Host header of an HTTP request.
func parseHostHeader(data []byte) (string, string, error) {
	for _, line := range strings.Split(string(data), "\r\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "Host") {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" {
			break
		}
		if h, p, err := net.SplitHostPort(v); err == nil {
			if _, err := strconv.Atoi(p); err == nil {
				return h, p, nil
			}
		}
		return strings.Trim(v, "[]"), "80", nil
	}
	return "", "", errors.New("HTTP without Host header")
}

// parseSNI returns the server name of a TLS ClientHello record, or "".
func parseSNI(rec []byte) string {
	if len(rec) < 5 || rec[0] != 0x16 {
		return ""
	}
	p := rec[5:]
	// handshake header: type(1) length(3)
	if len(p) < 4 || p[0] != 0x01 {
		return ""
	}
	p = p[4:]
	skip := func(n int) bool {
		if len(p) < n {
			return false
		}
		p = p[n:]
		return true
	}
	if !skip(2+32) || len(p) < 1 { // version, random
		return ""
	}
	if !skip(1+int(p[0])) || len(p) < 2 { // session id
		return ""
	}
	if !skip(2+int(p[0])<<8+int(p[1])) || len(p) < 1 { // cipher suites
		return ""
	}
	if !skip(1+int(p[0])) || len(p) < 2 { // compression
		return ""
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if extLen < len(p) {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		typ := int(p[0])<<8 | int(p[1])
		l := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if l > len(p) {
			return ""
		}
		if typ == 0 { // server_name
			e := p[:l]
			if len(e) < 5 {
				return ""
			}
			// list length(2) name type(1) name length(2)
			nl := int(e[3])<<8 | int(e[4])
			if e[2] != 0 || 5+nl > len(e) {
				return ""
			}
			return string(e[5 : 5+nl])
		}
		p = p[l:]
	}
	return ""
}
