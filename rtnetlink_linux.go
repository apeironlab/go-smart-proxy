//go:build linux

package main

import (
	"log"
	"syscall"
	"time"
)

// init listens for Linux netlink route/link/address changes and triggers the
// same discovery path used by the periodic poll. The polling timer remains the
// fallback if netlink is unavailable.
func init() {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		log.Printf("[ERR] Could not create netlink listener: %v", err)
		return
	}
	sa := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: syscall.RTMGRP_LINK |
			syscall.RTMGRP_IPV4_IFADDR | syscall.RTMGRP_IPV6_IFADDR |
			syscall.RTMGRP_IPV4_ROUTE | syscall.RTMGRP_IPV6_ROUTE,
	}
	if err := syscall.Bind(fd, sa); err != nil {
		log.Printf("[ERR] Could not bind netlink listener: %v", err)
		return
	}

	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil {
				log.Printf("[ERR] Could not read netlink: %v", err)
				time.Sleep(time.Second)
				continue
			}
			msgs, err := syscall.ParseNetlinkMessage(buf[:n])
			if err != nil {
				log.Printf("[ERR] Could not parse netlink: %v", err)
				continue
			}
			for _, msg := range msgs {
				switch msg.Header.Type {
				case syscall.RTM_NEWLINK, syscall.RTM_DELLINK,
					syscall.RTM_NEWADDR, syscall.RTM_DELADDR,
					syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE:
					log.Printf("network change detected")
					discoverNetwork()
				}
			}
		}
	}()
}
