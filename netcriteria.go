package main

import (
	"fmt"
	"net"
	"strings"
)

// netCriteria are conditions on the local network. Every condition that is set
// must hold. Routes use them to know when they apply, and the labels shared
// with relay contacts use the same ones to know which label fits the network
// the device is on.
type netCriteria struct {
	Gateway string // the default gateway is this IP
	IFace   string // the default interface matches (names or globs)
	Net     string // an interface has an address in this CIDR (or this network)
	IFaceUp string // an interface matching these names or globs is in use
	VPN     string // "up": a VPN is active, "down": none is
}

// isEmpty reports whether no condition is set.
func (c netCriteria) isEmpty() bool {
	return c.Gateway == "" && c.IFace == "" && c.Net == "" && c.IFaceUp == "" && c.VPN == ""
}

// validate checks the syntax of the conditions.
func (c netCriteria) validate() error {
	if c.Gateway != "" && net.ParseIP(c.Gateway) == nil {
		return fmt.Errorf("gateway %q is not an IP address", c.Gateway)
	}
	if c.Net != "" {
		if _, _, err := net.ParseCIDR(c.Net); err != nil {
			return fmt.Errorf("network %q is not a CIDR (for instance 10.0.0.0/8)", c.Net)
		}
	}
	if v := strings.ToLower(strings.TrimSpace(c.VPN)); v != "" && v != "up" && v != "down" {
		return fmt.Errorf(`VPN must be empty, "up" or "down"`)
	}
	if !validLabelPattern(c.IFace) || !validLabelPattern(c.IFaceUp) {
		return fmt.Errorf("invalid interface pattern")
	}
	return nil
}

// match reports whether the network state satisfies every condition, and why
// not when it does not.
func (c netCriteria) match(st netState) (bool, string) {
	if c.Gateway != "" && (st.defaultGw == nil || st.defaultGw.String() != c.Gateway) {
		return false, fmt.Sprintf("gateway %s != %s", st.defaultGw.String(), c.Gateway)
	}
	if c.IFace != "" && !matchIface(c.IFace, st.iface.Name) {
		return false, fmt.Sprintf("default iface %q != %q", st.iface.Name, c.IFace)
	}
	if c.IFaceUp != "" {
		found := false
		for name := range st.analysis.Active {
			if matchIface(c.IFaceUp, name) {
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Sprintf("no active interface matches %q", c.IFaceUp)
		}
	}
	switch c.VPN {
	case "up":
		if len(st.analysis.VPN) == 0 {
			return false, "no VPN is active"
		}
	case "down":
		if len(st.analysis.VPN) > 0 {
			return false, fmt.Sprintf("a VPN is active (%s)", strings.Join(st.analysis.VPN, ", "))
		}
	}
	if c.Net != "" {
		found := false
		if st.networkNets[c.Net] {
			found = true
		} else {
			_, pNet, err := net.ParseCIDR(c.Net)
			if err == nil {
				for _, ip := range st.localIPs {
					if pNet.Contains(ip) {
						found = true
						break
					}
				}
			}
		}
		if !found {
			netStr := ""
			if st.network != nil {
				netStr = st.network.String()
			}
			return false, fmt.Sprintf("net %q not found (default is %q)", c.Net, netStr)
		}
	}
	return true, ""
}
