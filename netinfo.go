package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
)

// This file holds the platform-independent part of network and VPN detection:
// parsers for the routing tables of each operating system, the classification
// of network interfaces and the rules that decide whether a VPN is in use.
// The platform-specific files only read the raw routing table.

// routeEntry is one IPv4 entry of the routing table.
type routeEntry struct {
	Dest    *net.IPNet
	Gateway net.IP // nil for on-link routes
	Iface   string // interface name, when the table reports it
	IfaceIP net.IP // egress address, when the table reports that instead
	Metric  int
	// Scoped marks interface-scoped entries (BSD "I" flag): they are not used
	// for ordinary lookups, so they never decide the default interface.
	Scoped bool
}

func (e routeEntry) isDefault() bool {
	if e.Dest == nil {
		return false
	}
	ones, _ := e.Dest.Mask.Size()
	return ones == 0
}

// ifaceData is the part of net.Interface the detection needs, so that it can
// be exercised in tests without touching the system.
type ifaceData struct {
	Name  string
	Flags net.Flags
	IPs   []net.IP
}

// ifaceStatus is the detection result for one interface. It is also what the
// web UI shows to explain a decision.
type ifaceStatus struct {
	Name    string   `json:"name"`
	Up      bool     `json:"up"`
	Addrs   []string `json:"addrs"`
	VPNLike bool     `json:"vpnLike"`
	Routed  bool     `json:"routed"`
	Default bool     `json:"default"`
	// Active: up, has a usable IPv4 address and carries routes. Leftover
	// tunnel interfaces that VPN clients leave behind are not active.
	Active bool `json:"active"`
	// VPN: an active interface that looks like a tunnel.
	VPN bool `json:"vpn"`
}

// netAnalysis is the full result of one detection pass.
type netAnalysis struct {
	Ifaces       []ifaceStatus
	DefaultIface string
	DefaultGW    net.IP
	Active       map[string]bool
	VPN          []string // sorted names of the active VPN interfaces
}

// signature identifies the detection result, to notice changes that do not
// alter the default route (a split-tunnel VPN connecting, for instance).
func (a netAnalysis) signature() string {
	var parts []string
	for _, i := range a.Ifaces {
		if i.Active {
			parts = append(parts, i.Name)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",") + "|" + strings.Join(a.VPN, ",")
}

// ---------------------------------------------------------------------------
// Interface classification
// ---------------------------------------------------------------------------

var vpnNamePrefixes = []string{
	"utun", "tun", "tap", "ppp", "wg", "ipsec", "gpd", "zt", "nordlynx", "wintun",
}

var vpnNameParts = []string{
	"vpn", "pulse", "ivanti", "anyconnect", "cisco", "forti", "globalprotect", "pangp",
	"zscaler", "openvpn", "wireguard", "tailscale", "zerotier", "nord", "proton", "softether",
	"juniper", "checkpoint", "sonicwall", "netextender", "tap-windows", "wan miniport",
	"surfshark", "expressvpn", "mullvad",
}

// virtualNameParts lists virtual interfaces that are never a VPN even though
// they are point-to-point or look like a tunnel.
var virtualNameParts = []string{
	"docker", "veth", "virbr", "vmnet", "vboxnet", "vethernet", "hyper-v", "wsl", "br-",
	"bridge", "awdl", "llw", "anpi", "lo",
}

// looksLikeVPN reports whether an interface name is typical of a VPN tunnel.
// Names are a hint: tunnels are also recognized by being point-to-point.
func looksLikeVPN(name string) bool {
	n := strings.ToLower(name)
	for _, v := range virtualNameParts {
		if n == v || (len(v) > 2 && strings.Contains(n, v)) {
			return false
		}
	}
	for _, p := range vpnNamePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	for _, p := range vpnNameParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// matchIface reports whether name matches any of the comma-separated patterns.
// A pattern is an interface name or a glob ("utun*", "Pulse*"); case is ignored.
func matchIface(patterns, name string) bool {
	n := strings.ToLower(name)
	for _, p := range strings.Split(patterns, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if p == n {
			return true
		}
		if strings.ContainsAny(p, "*?[") {
			if ok, err := path.Match(p, n); err == nil && ok {
				return true
			}
		}
	}
	return false
}

// usableIPv4 reports whether an address can carry traffic: not loopback, not
// link-local and not unspecified.
func usableIPv4(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && !v4.IsLoopback() && !v4.IsLinkLocalUnicast() && !v4.IsUnspecified()
}

// ignorableRoute reports whether a route says nothing about where traffic goes:
// loopback, link-local, multicast and broadcast.
func ignorableRoute(e routeEntry) bool {
	if e.Dest == nil {
		return true
	}
	ip := e.Dest.IP.To4()
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return true
	}
	if ip.Equal(net.IPv4bcast) || ip.Equal(net.IPv4zero) && !e.isDefault() {
		return true
	}
	return false
}

// analyzeNetwork combines the routing table and the interface list. The route
// table is what tells a live VPN from a leftover tunnel interface.
func analyzeNetwork(routes []routeEntry, ifaces []ifaceData) netAnalysis {
	// Map egress addresses to interface names for tables that report addresses.
	byIP := map[string]string{}
	for _, i := range ifaces {
		for _, ip := range i.IPs {
			byIP[ip.String()] = i.Name
		}
	}
	nameOf := func(e routeEntry) string {
		if e.Iface != "" {
			return e.Iface
		}
		if e.IfaceIP != nil {
			return byIP[e.IfaceIP.String()]
		}
		return ""
	}

	res := netAnalysis{Active: map[string]bool{}}

	// Default route: lowest metric among unscoped default entries whose
	// interface is known; the table order breaks ties.
	best := -1
	for i, e := range routes {
		if !e.isDefault() || e.Scoped || nameOf(e) == "" {
			continue
		}
		if best < 0 || e.Metric < routes[best].Metric {
			best = i
		}
	}
	if best >= 0 {
		res.DefaultIface = nameOf(routes[best])
		res.DefaultGW = routes[best].Gateway
	}

	routed := map[string]bool{}
	for _, e := range routes {
		if e.Scoped || ignorableRoute(e) && !e.isDefault() {
			continue
		}
		if n := nameOf(e); n != "" {
			routed[n] = true
		}
	}

	for _, i := range ifaces {
		st := ifaceStatus{
			Name:    i.Name,
			Up:      i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0,
			Routed:  routed[i.Name],
			Default: i.Name == res.DefaultIface,
		}
		hasAddr := false
		for _, ip := range i.IPs {
			st.Addrs = append(st.Addrs, ip.String())
			if usableIPv4(ip) {
				hasAddr = true
			}
		}
		tunnel := i.Flags&net.FlagPointToPoint != 0 || looksLikeVPN(i.Name)
		for _, v := range virtualNameParts {
			n := strings.ToLower(i.Name)
			if n == v || (len(v) > 2 && strings.Contains(n, v)) {
				tunnel = false
			}
		}
		st.VPNLike = tunnel
		st.Active = st.Up && hasAddr && (st.Routed || st.Default)
		st.VPN = st.Active && tunnel
		if st.Active {
			res.Active[st.Name] = true
		}
		if st.VPN {
			res.VPN = append(res.VPN, st.Name)
		}
		res.Ifaces = append(res.Ifaces, st)
	}
	sort.Strings(res.VPN)
	sort.Slice(res.Ifaces, func(a, b int) bool { return res.Ifaces[a].Name < res.Ifaces[b].Name })
	return res
}

// ---------------------------------------------------------------------------
// Routing table parsers
// ---------------------------------------------------------------------------

// parseLinuxRoutes parses /proc/net/route.
func parseLinuxRoutes(data string) []routeEntry {
	var out []routeEntry
	for i, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 8 {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x1 == 0 { // RTF_UP
			continue
		}
		dest, ok1 := hexIPv4(f[1])
		gw, ok2 := hexIPv4(f[2])
		mask, ok3 := hexIPv4(f[7])
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		e := routeEntry{
			Dest:   &net.IPNet{IP: dest, Mask: net.IPMask(mask)},
			Iface:  f[0],
			Metric: metric,
		}
		if flags&0x2 != 0 && !gw.IsUnspecified() { // RTF_GATEWAY
			e.Gateway = gw
		}
		out = append(out, e)
	}
	return out
}

// hexIPv4 decodes the little-endian hex form used by /proc/net/route.
func hexIPv4(s string) (net.IP, bool) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil, false
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return net.IP(b), true
}

// parseBSDRoutes parses `netstat -rn -f inet` as printed by macOS and the BSDs.
func parseBSDRoutes(data string) []routeEntry {
	var out []routeEntry
	netif, flagsCol := -1, -1
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "Destination" {
			for i, h := range f {
				switch strings.ToLower(h) {
				case "netif", "iface", "interface":
					netif = i
				case "flags":
					flagsCol = i
				}
			}
			continue
		}
		if netif < 0 || flagsCol < 0 || len(f) <= netif {
			continue
		}
		dest, ok := parseBSDDest(f[0])
		if !ok {
			continue
		}
		flags := f[flagsCol]
		e := routeEntry{Dest: dest, Iface: f[netif], Scoped: strings.Contains(flags, "I")}
		if gw := net.ParseIP(f[1]); gw != nil && strings.Contains(flags, "G") {
			e.Gateway = gw
		}
		// BSD tables have no metric: keep the table order by using the line
		// position as a tie-breaker (earlier entries win).
		e.Metric = len(out)
		out = append(out, e)
	}
	return out
}

// parseBSDDest understands "default", "10.0.0.0/8", "192.168.1" (a /24) and
// "10" (a /8), the abbreviated forms netstat prints.
func parseBSDDest(s string) (*net.IPNet, bool) {
	if s == "default" {
		return &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}, true
	}
	addr, maskStr, hasMask := strings.Cut(s, "/")
	// Strip an interface scope suffix such as "fe80::1%en0"; IPv4 only here.
	if strings.ContainsAny(addr, ":%") {
		return nil, false
	}
	octets := strings.Split(addr, ".")
	if len(octets) == 0 || len(octets) > 4 {
		return nil, false
	}
	ip := make([]byte, 4)
	for i, o := range octets {
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 {
			return nil, false
		}
		ip[i] = byte(n)
	}
	ones := 8 * len(octets)
	if hasMask {
		m, err := strconv.Atoi(maskStr)
		if err != nil || m < 0 || m > 32 {
			return nil, false
		}
		ones = m
	}
	return &net.IPNet{IP: net.IP(ip).Mask(net.CIDRMask(ones, 32)), Mask: net.CIDRMask(ones, 32)}, true
}

// parseWindowsRoutes parses `route print -4`. Only the numeric columns are
// read (destination, mask, ... interface address, metric), so the output
// language does not matter: the gateway column may say "On-link" or a
// localized, possibly multi-word, equivalent ("In collegamento").
func parseWindowsRoutes(data string) []routeEntry {
	var out []routeEntry
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		dest, mask := net.ParseIP(f[0]), net.ParseIP(f[1])
		ifIP := net.ParseIP(f[len(f)-2])
		metric, err := strconv.Atoi(f[len(f)-1])
		if dest == nil || mask == nil || ifIP == nil || err != nil || dest.To4() == nil || mask.To4() == nil || ifIP.To4() == nil {
			continue
		}
		e := routeEntry{
			Dest:    &net.IPNet{IP: dest.To4(), Mask: net.IPMask(mask.To4())},
			IfaceIP: ifIP.To4(),
			Metric:  metric,
		}
		// A gateway is a single address; anything else is "on-link".
		if len(f) == 5 {
			if gw := net.ParseIP(f[2]); gw != nil && !gw.IsUnspecified() {
				e.Gateway = gw.To4()
			}
		}
		out = append(out, e)
	}
	return out
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

func systemInterfaces() []ifaceData {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]ifaceData, 0, len(ifs))
	for _, i := range ifs {
		d := ifaceData{Name: i.Name, Flags: i.Flags}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				d.IPs = append(d.IPs, v.IP)
			case *net.IPAddr:
				d.IPs = append(d.IPs, v.IP)
			}
		}
		out = append(out, d)
	}
	return out
}

// detectNetwork reads the routing table and the interfaces. When the routing
// table cannot be read the result still lists the interfaces, but cannot tell
// a live tunnel from a leftover one, so no VPN is reported.
func detectNetwork() (netAnalysis, error) {
	ifaces := systemInterfaces()
	routes, err := readRouteTable()
	if err != nil {
		a := analyzeNetwork(nil, ifaces)
		a.VPN = nil
		for i := range a.Ifaces {
			a.Ifaces[i].VPN = false
		}
		return a, fmt.Errorf("routing table: %w", err)
	}
	return analyzeNetwork(routes, ifaces), nil
}

// defaultRouteInfo returns the gateway and the interface of the real default
// route. Reading the routing table (instead of guessing from an outbound
// socket) gives the actual gateway on every platform and is not fooled by
// tunnel interfaces that VPN clients leave behind.
func defaultRouteInfo() (gateway, ifaceName string, err error) {
	a, err := detectNetwork()
	if a.DefaultIface == "" {
		if err == nil {
			err = errors.New("no default route")
		}
		return "", "", err
	}
	if a.DefaultGW != nil {
		gateway = a.DefaultGW.String()
	}
	return gateway, a.DefaultIface, nil
}
