package main

import (
	"fmt"
	"log"
	"syscall"
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
			}

			for _, msg := range msgs {
				if _, ok := msg.(*syscall.InterfaceAddrMessage); ok {
					log.Printf("address change!")
					discoverNetwork()
				}
			}
		}
	}()
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

func (l *NetlinkListener) ReadMsgs() ([]syscall.RoutingMessage, error) {
	defer func() {
		recover()
	}()

	pkt := make([]byte, 2048)

	n, err := syscall.Read(l.fd, pkt)
	if err != nil {
		return nil, fmt.Errorf("read: %s", err)
	}

	msgs, err := syscall.ParseRoutingMessage(pkt[:n])
	if err != nil {
		return nil, fmt.Errorf("parse: %s", err)
	}

	return msgs, nil
}
