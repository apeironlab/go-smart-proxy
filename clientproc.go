package main

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

// ProcessRef names a process in the chain of parents of a client.
type ProcessRef struct {
	PID  int    `json:"pid"`
	Name string `json:"name,omitempty"`
	Exe  string `json:"exe,omitempty"`
}

// ClientProcess is what the system says about the program that opened a
// connection to the proxy. Every field is best effort: a program may have
// ended before it could be read, belong to another user, or the system may not
// say. The information is shown to the user and never used to allow or refuse
// a connection.
type ClientProcess struct {
	PID     int          `json:"pid"`
	Name    string       `json:"name,omitempty"`
	Exe     string       `json:"exe,omitempty"`
	Cmdline string       `json:"cmdline,omitempty"`
	User    string       `json:"user,omitempty"`
	Started *time.Time   `json:"started,omitempty"`
	Window  string       `json:"window,omitempty"` // title of the program's main window, when it has one
	Parents []ProcessRef `json:"parents,omitempty"`
	Note    string       `json:"note,omitempty"` // why something is missing
}

// App is how the table names the client: the title of its main window if it
// has one, else the name of its executable.
func (p *ClientProcess) App() string {
	if p == nil {
		return ""
	}
	if w := strings.TrimSpace(p.Window); w != "" {
		return w
	}
	return p.Name
}

// clientProcessLookup finds the process behind a client address. It is a
// variable so that tests can replace it; each operating system sets it in its
// own file.
var clientProcessLookup = func(ip net.IP, port int) (*ClientProcess, error) { return nil, errClientProcessUnsupported }

// splitClientAddr returns the address of a client when it can be a program on
// this machine: an IP address that belongs to it, with a port. Clients of the
// relay (e-mail addresses) and addresses of other computers give false.
func splitClientAddr(client string) (net.IP, int, bool) {
	host, portStr, err := net.SplitHostPort(client)
	if err != nil {
		return nil, 0, false
	}
	ip := net.ParseIP(host)
	port := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return nil, 0, false
		}
		port = port*10 + int(c-'0')
		if port > 65535 {
			return nil, 0, false
		}
	}
	if ip == nil || port == 0 {
		return nil, 0, false
	}
	if ip.IsLoopback() || isLocalAddress(ip) {
		return ip, port, true
	}
	return nil, 0, false
}

func isLocalAddress(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// processCache keeps what was read about a process for a few seconds: a
// program usually opens many connections, and reading the system for each one
// would cost more than the connection.
type processCache struct {
	mu      sync.Mutex
	entries map[int]processCacheEntry
}

type processCacheEntry struct {
	at   time.Time
	proc *ClientProcess
}

const processCacheTTL = 5 * time.Second

var procCache = &processCache{entries: map[int]processCacheEntry{}}

func (c *processCache) get(pid int) (*ClientProcess, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[pid]
	if !ok || time.Since(e.at) > processCacheTTL {
		return nil, false
	}
	cp := *e.proc
	return &cp, true
}

func (c *processCache) put(pid int, p *ClientProcess) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > 256 {
		for k, e := range c.entries {
			if time.Since(e.at) > processCacheTTL {
				delete(c.entries, k)
			}
		}
	}
	cp := *p
	c.entries[pid] = processCacheEntry{at: time.Now(), proc: &cp}
}

// describeClient is what the connection registry calls: it never fails, it
// returns what it could read, or nil when the client is not on this machine or
// the system does not say.
func describeClient(client string) *ClientProcess {
	ip, port, ok := splitClientAddr(client)
	if !ok {
		return nil
	}
	p, err := clientProcessLookup(ip, port)
	if err != nil || p == nil {
		if err == errClientProcessUnsupported {
			return nil
		}
		note := "unknown"
		if err != nil {
			note = err.Error()
		}
		return &ClientProcess{Note: note}
	}
	return p
}

type clientProcessError string

func (e clientProcessError) Error() string { return string(e) }

const (
	errClientProcessUnsupported = clientProcessError("not available on this system")
	errClientProcessNotFound    = clientProcessError("the program ended, or belongs to another user")
)

const (
	afINET  = 2  // AF_INET
	afINET6 = 23 // AF_INET6 on Windows
)

// findInWindowsTable walks MIB_TCPTABLE_OWNER_PID (IPv4) or
// MIB_TCP6TABLE_OWNER_PID (IPv6): a count, then rows. Ports are in network
// order in the low 16 bits of a 32-bit value.
func findInWindowsTable(buf []byte, family uint32, ip net.IP, port int) (int, bool) {
	n := int(binary.LittleEndian.Uint32(buf))
	var rowSize, local, lport, pidOff int
	if family == afINET {
		rowSize, local, lport, pidOff = 24, 4, 8, 20 // state, laddr, lport, raddr, rport, pid
	} else {
		rowSize, local, lport, pidOff = 56, 0, 20, 52 // laddr[16], scope, lport, raddr[16], scope, rport, state, pid
	}
	for i := 0; i < n; i++ {
		row := 4 + i*rowSize
		if row+rowSize > len(buf) {
			break
		}
		addrLen := 4
		if family == afINET6 {
			addrLen = 16
		}
		if !net.IP(buf[row+local : row+local+addrLen]).Equal(ip) {
			continue
		}
		raw := binary.LittleEndian.Uint32(buf[row+lport:])
		if int((raw&0xff)<<8|(raw>>8)&0xff) != port {
			continue
		}
		return int(binary.LittleEndian.Uint32(buf[row+pidOff:])), true
	}
	return 0, false
}

// parseLsofOwner reads the output of `lsof -F pcn` and returns the program
// that has a connection whose local end is local ("127.0.0.1:54321" or
// "[::1]:54321"). lsof shows each connection as "local->remote" under the
// program that owns it; the proxy's own end shows as "remote->local".
func parseLsofOwner(out, local string) (pid int, name string, ok bool) {
	curPID, curName := 0, ""
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			curPID = 0
			for _, c := range line[1:] {
				if c < '0' || c > '9' {
					curPID = 0
					break
				}
				curPID = curPID*10 + int(c-'0')
			}
			curName = ""
		case 'c':
			curName = line[1:]
		case 'n':
			if curPID != 0 && strings.HasPrefix(line[1:], local+"->") {
				return curPID, curName, true
			}
		}
	}
	return 0, "", false
}
