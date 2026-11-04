package blocklist

import (
	"net/netip"
	"strings"
)

// Matcher answers whether a host is on a set of lists. A domain on a list
// blocks itself and every subdomain; an address or network blocks the hosts
// that are addresses in it. It is read-only once built, so it can be used from
// many goroutines.
type Matcher struct {
	domains map[string]uint16 // domain -> index in sources
	sources []string
	nets    []netEntry
	count   int
}

type netEntry struct {
	p   netip.Prefix
	src uint16
}

// Hit says what blocked a host.
type Hit struct {
	Source string // name of the list or rule
	Rule   string // the domain or network that matched
}

// Builder collects lists into a Matcher.
type Builder struct {
	m *Matcher
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder {
	return &Builder{m: &Matcher{domains: map[string]uint16{}}}
}

// Add puts the entries of one source in. The first source to name a domain
// keeps the credit for it.
func (b *Builder) Add(source string, domains []string, nets []netip.Prefix) {
	idx := uint16(len(b.m.sources))
	if len(b.m.sources) >= 65535 {
		idx = 65535
	} else {
		b.m.sources = append(b.m.sources, source)
	}
	for _, d := range domains {
		if d, ok := NormalizeDomain(d); ok {
			if _, dup := b.m.domains[d]; !dup {
				b.m.domains[d] = idx
			}
		}
	}
	for _, p := range nets {
		b.m.nets = append(b.m.nets, netEntry{p: p, src: idx})
	}
}

// Build returns the matcher; the builder must not be used afterwards.
func (b *Builder) Build() *Matcher {
	b.m.count = len(b.m.domains) + len(b.m.nets)
	m := b.m
	b.m = nil
	return m
}

// Len is the number of entries.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return m.count
}

func (m *Matcher) source(i uint16) string {
	if int(i) < len(m.sources) {
		return m.sources[i]
	}
	return "?"
}

// Match reports whether host is blocked, and by what. host may carry a port,
// brackets (IPv6) or a trailing dot.
func (m *Matcher) Match(host string) (Hit, bool) {
	if m == nil || m.count == 0 {
		return Hit{}, false
	}
	host = CleanHost(host)
	if host == "" {
		return Hit{}, false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		for _, e := range m.nets {
			if e.p.Contains(a) {
				return Hit{Source: m.source(e.src), Rule: e.p.String()}, true
			}
		}
		return Hit{}, false
	}
	// The host, then each parent domain: a.b.example.com, b.example.com,
	// example.com, com.
	for d := host; ; {
		if i, ok := m.domains[d]; ok {
			return Hit{Source: m.source(i), Rule: d}, true
		}
		dot := strings.IndexByte(d, '.')
		if dot < 0 {
			return Hit{}, false
		}
		d = d[dot+1:]
	}
}

// CleanHost lowercases a host and removes a port, IPv6 brackets and a trailing dot.
func CleanHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			h = h[1:i]
		}
	} else if i := strings.LastIndexByte(h, ':'); i > 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// Decision is the verdict on a host.
type Decision struct {
	Blocked   bool
	Mandatory bool // blocked by a rule the user cannot switch off
	Hit       Hit
}

// Decide applies the layers in order of strength:
//
//  1. a mandatory matcher blocks, whatever the user allowed;
//  2. otherwise the allow matcher lets the host through;
//  3. otherwise an optional matcher may block it.
func Decide(host string, mandatory []*Matcher, allow *Matcher, optional []*Matcher) Decision {
	for _, m := range mandatory {
		if h, ok := m.Match(host); ok {
			return Decision{Blocked: true, Mandatory: true, Hit: h}
		}
	}
	if _, ok := allow.Match(host); ok {
		return Decision{}
	}
	for _, m := range optional {
		if h, ok := m.Match(host); ok {
			return Decision{Blocked: true, Hit: h}
		}
	}
	return Decision{}
}
