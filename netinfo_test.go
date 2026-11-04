package main

import (
	"net"
	"reflect"
	"testing"
)

const linuxRouteSplitVPN = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0100A8C0	0003	0	0	600	00000000	0	0	0
wlan0	0000A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
tun0	0000000A	0108000A	0003	0	0	0	000000FF	0	0	0
tun0	0008000A	00000000	0001	0	0	0	00FFFFFF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
wlan0	0000FEA9	00000000	0001	0	0	1000	0000FFFF	0	0	0
`

const darwinNetstatLeftover = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            link#14            UCSIg               utun4
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
169.254            link#6             UCS                   en0
192.168.1          link#6             UCS                   en0
192.168.1.1/32     link#6             UCS                   en0
224.0.0/4          link#6             UmCS                  en0
255.255.255.255/32 link#6             UCS                   en0
`

const darwinNetstatSplit = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
10                 10.8.0.2           UGSc                utun4
10.8.0.2           10.8.0.1           UH                  utun4
172.16/12          10.8.0.2           UGSc                utun4
192.168.1          link#6             UCS                   en0
`

const darwinNetstatFullTunnel = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
0/1                10.8.0.2           UGSc                utun4
default            192.168.1.1        UGScI                 en0
default            10.8.0.2           UGScg               utun4
128.0/1            10.8.0.2           UGSc                utun4
`

const windowsRouteEnglish = `===========================================================================
Interface List
  7...00 ff 12 34 56 78 ......TAP-Windows Adapter V9
 12...a4 bb 6d 11 22 33 ......Intel(R) Wi-Fi 6 AX201 160MHz
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     35
         10.0.0.0        255.0.0.0         10.8.0.1        10.8.0.2    291
         10.8.0.0    255.255.255.0         On-link         10.8.0.2    291
         10.8.0.2  255.255.255.255         On-link         10.8.0.2    291
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link     192.168.1.50    291
      224.0.0.0        240.0.0.0         On-link     192.168.1.50    291
255.255.255.255  255.255.255.255         On-link     192.168.1.50    291
===========================================================================
Persistent Routes:
  None
`

// Italian output: the gateway column says "In collegamento" instead of "On-link".
const windowsRouteItalian = `Tabella route IPv4
===========================================================================
Route attive:
  Indirizzo rete          Mask              Gateway       Interfaccia  Metrica
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     35
      192.168.1.0    255.255.255.0  In collegamento     192.168.1.50    291
===========================================================================
Route permanenti:
  Indirizzo rete  Mask    Indirizzo gateway  Metrica
          0.0.0.0          0.0.0.0      192.168.1.1  Predefinita
`

func ifc(name string, flags net.Flags, ips ...string) ifaceData {
	d := ifaceData{Name: name, Flags: flags}
	for _, s := range ips {
		d.IPs = append(d.IPs, net.ParseIP(s))
	}
	return d
}

const (
	up  = net.FlagUp | net.FlagBroadcast | net.FlagMulticast
	p2p = net.FlagUp | net.FlagPointToPoint | net.FlagMulticast
)

func TestParseLinuxRoutes(t *testing.T) {
	rs := parseLinuxRoutes(linuxRouteSplitVPN)
	if len(rs) != 6 {
		t.Fatalf("got %d routes", len(rs))
	}
	if !rs[0].isDefault() || rs[0].Gateway.String() != "192.168.0.1" || rs[0].Iface != "wlan0" || rs[0].Metric != 600 {
		t.Fatalf("default route parsed wrongly: %+v", rs[0])
	}
	if rs[2].Dest.String() != "10.0.0.0/8" || rs[2].Iface != "tun0" {
		t.Fatalf("split route: %+v", rs[2])
	}
	if rs[1].Gateway != nil {
		t.Fatalf("connected route must have no gateway: %+v", rs[1])
	}
}

func TestParseBSDDest(t *testing.T) {
	for in, want := range map[string]string{
		"default": "0.0.0.0/0", "10": "10.0.0.0/8", "172.16/12": "172.16.0.0/12", "192.168.1": "192.168.1.0/24",
		"10.8.0.2": "10.8.0.2/32", "224.0.0/4": "224.0.0.0/4", "0/1": "0.0.0.0/1", "128.0/1": "128.0.0.0/1",
	} {
		got, ok := parseBSDDest(in)
		if !ok || got.String() != want {
			t.Errorf("parseBSDDest(%q) = %v, %v; want %s", in, got, ok, want)
		}
	}
	for _, in := range []string{"fe80::1%en0", "ff02::/16", "x.y", "300.1.1.1"} {
		if _, ok := parseBSDDest(in); ok {
			t.Errorf("parseBSDDest(%q) must fail", in)
		}
	}
}

func TestParseWindowsRoutesIgnoresLocale(t *testing.T) {
	en := parseWindowsRoutes(windowsRouteEnglish)
	if len(en) != 8 {
		t.Fatalf("english: %d routes", len(en))
	}
	if !en[0].isDefault() || en[0].Gateway.String() != "192.168.1.1" || en[0].IfaceIP.String() != "192.168.1.50" || en[0].Metric != 35 {
		t.Fatalf("default: %+v", en[0])
	}
	if en[2].Gateway != nil {
		t.Fatal("On-link must have no gateway")
	}
	it := parseWindowsRoutes(windowsRouteItalian)
	if len(it) != 2 || it[1].Gateway != nil {
		t.Fatalf("italian output (localized on-link, persistent routes section): %+v", it)
	}
}

func TestLooksLikeVPN(t *testing.T) {
	vpn := []string{"utun4", "tun0", "tap0", "ppp0", "wg0", "gpd0", "tailscale0", "Pulse Secure", "Ivanti Secure Access Client",
		"Cisco AnyConnect Secure Mobility Client Connection", "PANGP Virtual Ethernet Adapter", "OpenVPN TAP-Windows6", "ZeroTier One [abc]", "NordLynx", "Ethernet 3 VPN"}
	for _, n := range vpn {
		if !looksLikeVPN(n) {
			t.Errorf("%q should look like a VPN", n)
		}
	}
	notVPN := []string{"en0", "wlan0", "eth0", "lo", "lo0", "docker0", "veth1234", "virbr0", "br-1a2b", "vboxnet0", "vEthernet (WSL)", "awdl0", "bridge100", "Wi-Fi", "Ethernet"}
	for _, n := range notVPN {
		if looksLikeVPN(n) {
			t.Errorf("%q must not look like a VPN", n)
		}
	}
}

func TestMatchIface(t *testing.T) {
	cases := []struct {
		patterns, name string
		want           bool
	}{
		{"utun4", "utun4", true}, {"UTUN4", "utun4", true}, {"utun*", "utun7", true}, {"tun0, utun4", "utun4", true},
		{"Pulse*", "Pulse Secure", true}, {"utun4", "utun5", false}, {"", "utun4", false}, {"en?", "en0", true}, {"en?", "en10", false},
	}
	for _, c := range cases {
		if got := matchIface(c.patterns, c.name); got != c.want {
			t.Errorf("matchIface(%q, %q) = %v", c.patterns, c.name, got)
		}
	}
}

func TestAnalyzeNoVPN(t *testing.T) {
	a := analyzeNetwork(parseBSDRoutes(darwinNetstatLeftover), []ifaceData{
		ifc("lo0", net.FlagUp|net.FlagLoopback, "127.0.0.1"),
		ifc("en0", up, "192.168.1.50", "fe80::1"),
		// Leftover tunnel: up, but with no IPv4 address (only link-local IPv6).
		ifc("utun4", p2p, "fe80::abcd"),
		ifc("utun0", p2p, "fe80::1234"),
	})
	if a.DefaultIface != "en0" || a.DefaultGW.String() != "192.168.1.1" {
		t.Fatalf("default: %s via %v", a.DefaultIface, a.DefaultGW)
	}
	if len(a.VPN) != 0 {
		t.Fatalf("leftover tunnels must not count as a VPN: %v", a.VPN)
	}
}

func TestAnalyzeLeftoverTunnelWithAddressButNoRoutes(t *testing.T) {
	// The scoped default of utun4 ("I" flag) is not a real route.
	a := analyzeNetwork(parseBSDRoutes(darwinNetstatLeftover), []ifaceData{
		ifc("en0", up, "192.168.1.50"),
		ifc("utun4", p2p, "10.8.0.2"),
	})
	if len(a.VPN) != 0 {
		t.Fatalf("a tunnel with an address but no live route is not a VPN: %v", a.VPN)
	}
}

func TestAnalyzeSplitTunnelDarwin(t *testing.T) {
	a := analyzeNetwork(parseBSDRoutes(darwinNetstatSplit), []ifaceData{
		ifc("en0", up, "192.168.1.50"),
		ifc("utun4", p2p, "10.8.0.2"),
	})
	if a.DefaultIface != "en0" {
		t.Fatalf("a split tunnel keeps the default on en0, got %s", a.DefaultIface)
	}
	if !reflect.DeepEqual(a.VPN, []string{"utun4"}) {
		t.Fatalf("split-tunnel VPN must be detected: %v", a.VPN)
	}
}

func TestAnalyzeFullTunnelDarwin(t *testing.T) {
	a := analyzeNetwork(parseBSDRoutes(darwinNetstatFullTunnel), []ifaceData{
		ifc("en0", up, "192.168.1.50"),
		ifc("utun4", p2p, "10.8.0.2"),
	})
	// The scoped en0 default must not win; the VPN default does.
	if a.DefaultIface != "utun4" || !reflect.DeepEqual(a.VPN, []string{"utun4"}) {
		t.Fatalf("full tunnel: default=%s vpn=%v", a.DefaultIface, a.VPN)
	}
}

func TestAnalyzeLinuxSplitTunnelIgnoresDocker(t *testing.T) {
	a := analyzeNetwork(parseLinuxRoutes(linuxRouteSplitVPN), []ifaceData{
		ifc("lo", net.FlagUp|net.FlagLoopback, "127.0.0.1"),
		ifc("wlan0", up, "192.168.0.50"),
		ifc("tun0", p2p, "10.8.0.2"),
		ifc("docker0", up, "172.17.0.1"),
	})
	if a.DefaultIface != "wlan0" || a.DefaultGW.String() != "192.168.0.1" {
		t.Fatalf("default: %s via %v", a.DefaultIface, a.DefaultGW)
	}
	if !reflect.DeepEqual(a.VPN, []string{"tun0"}) {
		t.Fatalf("VPN: %v (docker0 must not count)", a.VPN)
	}
	if !a.Active["docker0"] {
		t.Fatal("docker0 is active, just not a VPN")
	}
}

func TestAnalyzeWindowsMapsInterfaceByAddress(t *testing.T) {
	a := analyzeNetwork(parseWindowsRoutes(windowsRouteEnglish), []ifaceData{
		ifc("Wi-Fi", up, "192.168.1.50"),
		ifc("Ethernet 3", up, "10.8.0.2"), // the VPN's TAP adapter has no VPN-like name
		ifc("Loopback Pseudo-Interface 1", net.FlagUp|net.FlagLoopback, "127.0.0.1"),
	})
	if a.DefaultIface != "Wi-Fi" || a.DefaultGW.String() != "192.168.1.1" {
		t.Fatalf("default: %s via %v", a.DefaultIface, a.DefaultGW)
	}
	// "Ethernet 3" is active (it carries 10/8) but is neither point-to-point
	// nor named like a VPN: it is only reported as an active interface, which a
	// route can still target with IFaceUp.
	if len(a.VPN) != 0 || !a.Active["Ethernet 3"] {
		t.Fatalf("vpn=%v active=%v", a.VPN, a.Active)
	}
	b := analyzeNetwork(parseWindowsRoutes(windowsRouteEnglish), []ifaceData{
		ifc("Wi-Fi", up, "192.168.1.50"),
		ifc("OpenVPN TAP-Windows6", up, "10.8.0.2"),
	})
	if !reflect.DeepEqual(b.VPN, []string{"OpenVPN TAP-Windows6"}) {
		t.Fatalf("named VPN adapter: %v", b.VPN)
	}
}

func TestAnalyzeDownInterfaceIsNotActive(t *testing.T) {
	a := analyzeNetwork(parseLinuxRoutes(linuxRouteSplitVPN), []ifaceData{
		ifc("wlan0", up, "192.168.0.50"),
		ifc("tun0", net.FlagPointToPoint, "10.8.0.2"), // no FlagUp
	})
	if len(a.VPN) != 0 {
		t.Fatalf("down interface: %v", a.VPN)
	}
}

func TestSignatureChangesWhenVPNConnects(t *testing.T) {
	ifs := []ifaceData{ifc("en0", up, "192.168.1.50"), ifc("utun4", p2p, "10.8.0.2")}
	without := analyzeNetwork(parseBSDRoutes(darwinNetstatLeftover), ifs)
	with := analyzeNetwork(parseBSDRoutes(darwinNetstatSplit), ifs)
	if without.signature() == with.signature() {
		t.Fatal("connecting a split-tunnel VPN must change the signature, even though the default route did not change")
	}
}

func stateFor(a netAnalysis, defaultIface string) netState {
	return netState{
		iface:    net.Interface{Name: defaultIface},
		analysis: a,
	}
}

func TestRouteCriteriaVPNAndIfaceUp(t *testing.T) {
	vpnUp := analyzeNetwork(parseBSDRoutes(darwinNetstatSplit), []ifaceData{ifc("en0", up, "192.168.1.50"), ifc("utun4", p2p, "10.8.0.2")})
	vpnDown := analyzeNetwork(parseBSDRoutes(darwinNetstatLeftover), []ifaceData{ifc("en0", up, "192.168.1.50"), ifc("utun4", p2p, "fe80::1")})

	corp := &ProxyRoute{name: "Corp", vpn: "up", ifaceUp: "utun*"}
	home := &ProxyRoute{name: "Home", vpn: "down"}
	exact := &ProxyRoute{name: "Pulse", ifaceUp: "utun4"}
	other := &ProxyRoute{name: "Other", ifaceUp: "utun9"}
	byDefault := &ProxyRoute{name: "OnWifi", iface: "en*"}

	check := func(r *ProxyRoute, st netState, want bool) {
		t.Helper()
		got, why := r.applicable(st)
		if got != want {
			t.Errorf("%s: applicable=%v (%s), want %v", r.name, got, why, want)
		}
	}
	up := stateFor(vpnUp, "en0")
	down := stateFor(vpnDown, "en0")
	check(corp, up, true)
	check(corp, down, false)
	check(home, up, false)
	check(home, down, true)
	check(exact, up, true)
	check(exact, down, false)
	check(other, up, false)
	check(byDefault, up, true)
	check(byDefault, stateFor(vpnUp, "utun4"), false)

	if _, why := home.applicable(up); why == "" {
		t.Error("a refusal must explain itself")
	}
}

func TestNewProxyRouteRejectsBadVPNValue(t *testing.T) {
	if _, err := newProxyRoute(&ConfigRoute{Name: "x", VPN: "maybe"}); err == nil {
		t.Fatal("invalid VPN value must be rejected")
	}
	r, err := newProxyRoute(&ConfigRoute{Name: "x", VPN: " UP ", IFaceUp: " utun* "})
	if err != nil || r.vpn != "up" || r.ifaceUp != "utun*" {
		t.Fatalf("normalization: %+v %v", r, err)
	}
}
