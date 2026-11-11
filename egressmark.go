package main

import (
	"net"
	"syscall"
	"time"
)

// dialTCP is net.DialTimeout with the egress mark set (see egressmark_unix.go).
func dialTCP(network, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, Control: markEgress}
	return d.Dial(network, address)
}

// chainControl runs several dialer controls in order.
func chainControl(controls ...func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		for _, f := range controls {
			if f == nil {
				continue
			}
			if err := f(network, address, c); err != nil {
				return err
			}
		}
		return nil
	}
}
