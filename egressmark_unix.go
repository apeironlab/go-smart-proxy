//go:build darwin || linux

package main

import "syscall"

// egressTOS marks every connection this program opens towards the network.
// The packet filter rules of the transparent routing (pfroute_darwin.go) let
// marked packets through untouched: without the mark the traffic of the
// proxy itself would be redirected to the proxy again, in an endless loop.
const egressTOS = 0x20

// markEgress is a net.Dialer Control that sets the egress mark on the socket.
func markEgress(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, egressTOS)
	})
	if err != nil {
		return err
	}
	return serr
}
