// Package blocklist reads the lists used to block hosts (ads, trackers,
// malware: the hosts files, domain lists and adblock lists of pfBlockerNG and
// friends), keeps them in a form that answers "is this host blocked?" quickly,
// and downloads them with the care a program that fetches URLs needs.
package blocklist

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"strings"
)

// Format is how a list is written.
type Format string

const (
	// Auto decides line by line: ||domain^ is adblock, a line starting with an
	// address is a hosts file, anything else is a domain per line.
	Auto Format = "auto"
	// Hosts is a hosts file: "0.0.0.0 ads.example.com".
	Hosts Format = "hosts"
	// Domains is one domain (or address, or network) per line.
	Domains Format = "domains"
	// ABP is the part of an adblock list that names domains: ||ads.example.com^
	ABP Format = "abp"
)

// Valid reports whether f is a known format ("" means Auto).
func (f Format) Valid() bool {
	switch f {
	case "", Auto, Hosts, Domains, ABP:
		return true
	}
	return false
}

// MaxEntries bounds one list: a hostile or broken URL must not use all memory.
const MaxEntries = 3_000_000

var errTooMany = errors.New("the list has too many entries")

// hostsSkip are names hosts files list for the machine itself.
var hostsSkip = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// Parse reads a list. It returns the domains, and any addresses or networks
// (as prefixes), skipping what it does not understand: lists are written by
// many hands.
func Parse(r io.Reader, f Format) (domains []string, nets []netip.Prefix, err error) {
	if f == "" {
		f = Auto
	}
	if !f.Valid() {
		return nil, nil, errors.New("unknown list format " + string(f))
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' || line[0] == ';' {
			continue
		}
		var got []string
		switch {
		case f == ABP || (f == Auto && strings.HasPrefix(line, "||")):
			if d, ok := parseABP(line); ok {
				got = []string{d}
			}
		case f == Hosts || (f == Auto && startsWithAddr(line) && len(strings.Fields(line)) > 1):
			got = parseHostsLine(line)
		default:
			if i := strings.Index(line, "#"); i > 0 {
				line = strings.TrimSpace(line[:i])
			}
			if strings.ContainsAny(line, " \t") {
				continue
			}
			if p, ok := parseNet(line); ok {
				nets = append(nets, p)
				continue
			}
			if d, ok := NormalizeDomain(line); ok {
				got = []string{d}
			}
		}
		domains = append(domains, got...)
		if len(domains)+len(nets) > MaxEntries {
			return nil, nil, errTooMany
		}
	}
	return domains, nets, sc.Err()
}

func startsWithAddr(line string) bool {
	tok := line
	if i := strings.IndexAny(line, " \t"); i > 0 {
		tok = line[:i]
	}
	_, err := netip.ParseAddr(tok)
	return err == nil
}

func parseHostsLine(line string) []string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	if _, err := netip.ParseAddr(fields[0]); err != nil {
		return nil
	}
	var out []string
	for _, h := range fields[1:] {
		h = strings.ToLower(h)
		if hostsSkip[h] {
			continue
		}
		if d, ok := NormalizeDomain(h); ok {
			out = append(out, d)
		}
	}
	return out
}

// parseABP keeps plain domain rules: ||example.com^ (optionally with $third-party
// style options, which only narrow where it applies; here it blocks the host
// whatever). Exceptions (@@), cosmetic and path rules are not host rules.
func parseABP(line string) (string, bool) {
	if !strings.HasPrefix(line, "||") || strings.Contains(line, "##") || strings.Contains(line, "#@#") {
		return "", false
	}
	rest := line[2:]
	if i := strings.IndexByte(rest, '$'); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "^")
	if strings.ContainsAny(rest, "/^*?|") { // a path or wildcard: not a whole-host rule
		return "", false
	}
	return NormalizeDomain(rest)
}

func parseNet(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil && !a.IsUnspecified() {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// NormalizeDomain lowercases a domain, drops a leading "*." or "." and a
// trailing dot, and reports whether what is left looks like a host name.
func NormalizeDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false
	}
	prev := byte('.')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
		case c == '-':
			if prev == '.' {
				return "", false
			}
		case c == '.':
			if prev == '.' || prev == '-' {
				return "", false
			}
		default:
			return "", false
		}
		prev = c
	}
	if prev == '-' {
		return "", false
	}
	return s, true
}
