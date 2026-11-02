//go:build darwin

package main

import (
	"fmt"
	"log"
	"syscall"
	"time"
)

func init() {
	netlink, err := ListenNetlink()
	if err != nil {
		log.Printf("[ERR] Could not create netlink listener: %v", err)
		return
	}

	go func() {
		for {
			msgs, err := netlink.ReadMsgs()
			if err != nil {
				log.Printf("[ERR] Could not read netlink: %v", err)
				time.Sleep(time.Second)
				continue
			}

			for _, msg := range msgs {
				if isRouteChange(msg) {
					log.Printf("network change detected")
					discoverNetwork()
				}
			}
		}
	}()
}

func isRouteChange(msg syscall.RoutingMessage) bool {
	switch m := msg.(type) {
	case *syscall.RouteMessage:
		switch m.Header.Type {
		case syscall.RTM_ADD, syscall.RTM_DELETE,
			syscall.RTM_NEWADDR, syscall.RTM_DELADDR,
			syscall.RTM_IFINFO:
			return true
		}
		return false
	default:
		return false
	}
}

type NetlinkListener struct {
	fd int
}

func ListenNetlink() (*NetlinkListener, error) {
	s, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("socket: %s", err)
	}
	return &NetlinkListener{fd: s}, nil
}

func (l *NetlinkListener) ReadMsgs() (msgs []syscall.RoutingMessage, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic parsing routing message: %v", r)
		}
	}()

	pkt := make([]byte, 2048)

	n, err := syscall.Read(l.fd, pkt)
	if err != nil {
		return nil, fmt.Errorf("read: %s", err)
	}

	msgs, err = syscall.ParseRoutingMessage(pkt[:n])
	if err != nil {
		return nil, fmt.Errorf("parse: %s", err)
	}

	return msgs, nil
}
