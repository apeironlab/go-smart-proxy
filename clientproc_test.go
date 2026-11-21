package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSplitClientAddr(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:54321", "[::1]:54321"} {
		if _, _, good := splitClientAddr(ok); !good {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "nonsense", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:x", "127.0.0.1:99999", "ann@example.org", "203.0.113.7:5000"} {
		if _, _, good := splitClientAddr(bad); good {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAppIsTheWindowTitleOrTheName(t *testing.T) {
	if (*ClientProcess)(nil).App() != "" {
		t.Error("nil process")
	}
	if got := (&ClientProcess{Name: "git"}).App(); got != "git" {
		t.Errorf("name: %q", got)
	}
	if got := (&ClientProcess{Name: "code", Window: "  main.go - VS Code "}).App(); got != "main.go - VS Code" {
		t.Errorf("window: %q", got)
	}
}

func TestClientProcessReachesTheConnectionRecord(t *testing.T) {
	old := clientProcessLookup
	t.Cleanup(func() { clientProcessLookup = old })
	clientProcessLookup = func(ip net.IP, port int) (*ClientProcess, error) {
		if port == 40001 {
			return &ClientProcess{PID: 4242, Name: "git", Window: "", Parents: []ProcessRef{{PID: 1, Name: "init"}}}, nil
		}
		if port == 40002 {
			return nil, errClientProcessNotFound
		}
		return nil, errClientProcessUnsupported
	}
	rec := connReg.newConn("connect", "127.0.0.1:40001", "example.org", "example.org:443", "", "Direct", "", "CONNECT", "")
	other := connReg.newConn("connect", "127.0.0.1:40002", "example.org", "example.org:443", "", "Direct", "", "CONNECT", "")
	none := connReg.newConn("connect", "127.0.0.1:40003", "example.org", "example.org:443", "", "Direct", "", "CONNECT", "")
	relayExit := connReg.newConn("relay-exit", "ann@example.org", "example.org", "example.org:443", "", "relay", "", "", "")
	waitFor(t, "the process of the client", func() bool { return rec.snapshot().Process != nil && other.snapshot().Process != nil })
	s := rec.snapshot()
	if s.App != "git" || s.Process.PID != 4242 || len(s.Process.Parents) != 1 {
		t.Errorf("snapshot = %+v", s.Process)
	}
	if o := other.snapshot(); o.Process == nil || o.Process.Note == "" || o.App != "" {
		t.Errorf("a program that cannot be found says why: %+v", o.Process)
	}
	time.Sleep(50 * time.Millisecond)
	if none.snapshot().Process != nil {
		t.Error("a system without the lookup invented a process")
	}
	if relayExit.snapshot().Process != nil {
		t.Error("a client of the relay is not a program on this machine")
	}
	// the snapshot is a copy
	s.Process.Name = "changed"
	if rec.snapshot().Process.Name != "git" {
		t.Error("the record was changed through a snapshot")
	}
}

func TestProcessCacheExpires(t *testing.T) {
	c := &processCache{entries: map[int]processCacheEntry{}}
	if _, ok := c.get(1); ok {
		t.Error("an empty cache answered")
	}
	c.put(1, &ClientProcess{PID: 1, Name: "a"})
	if p, ok := c.get(1); !ok || p.Name != "a" {
		t.Error("a fresh entry was lost")
	}
	c.entries[1] = processCacheEntry{at: time.Now().Add(-time.Minute), proc: &ClientProcess{PID: 1}}
	if _, ok := c.get(1); ok {
		t.Error("an old entry was used")
	}
	for i := 0; i < 300; i++ {
		c.entries[1000+i] = processCacheEntry{at: time.Now().Add(-time.Minute), proc: &ClientProcess{}}
	}
	c.put(2, &ClientProcess{PID: 2})
	if len(c.entries) > 10 {
		t.Errorf("old entries were not dropped: %d", len(c.entries))
	}
}

func TestDescribeOurOwnClient(t *testing.T) {
	// A connection from this very program to a local listener: the lookup must
	// find this process, where the system allows it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			c.Read(buf)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := describeClient(c.LocalAddr().String())
	if p == nil {
		t.Skip("this system does not say which program owns a connection")
	}
	if p.PID != os.Getpid() {
		t.Fatalf("found %+v (note %q), want pid %d", p, p.Note, os.Getpid())
	}
	if p.Name == "" || p.Exe == "" {
		t.Errorf("no name or executable: %+v", p)
	}
	if len(p.Parents) == 0 {
		t.Errorf("no parents: %+v", p)
	}
	if p.User == "" || p.Started == nil || time.Since(*p.Started) < 0 {
		t.Errorf("user or start time: %+v", p)
	}
	if !strings.Contains(p.Cmdline, ".test") && p.Cmdline == "" {
		t.Errorf("command line: %q", p.Cmdline)
	}
	// a port nobody uses
	if q := describeClient("127.0.0.1:1"); q == nil || q.PID != 0 || q.Note == "" {
		t.Errorf("an unused port: %+v", q)
	}
}

func TestWindowsTableRows(t *testing.T) {
	put := func(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	port := func(p int) uint32 { return uint32((p&0xff)<<8 | (p>>8)&0xff) } // network order in the low 16 bits

	// IPv4: count, then rows of state, local address, local port, remote address, remote port, pid
	v4 := make([]byte, 4+2*24)
	put(v4, 0, 2)
	copy(v4[4+4:], net.ParseIP("127.0.0.1").To4())
	put(v4, 4+8, port(3128))
	put(v4, 4+20, 111)
	copy(v4[4+24+4:], net.ParseIP("127.0.0.1").To4())
	put(v4, 4+24+8, port(54321))
	put(v4, 4+24+20, 222)
	if pid, ok := findInWindowsTable(v4, afINET, net.ParseIP("127.0.0.1").To4(), 54321); !ok || pid != 222 {
		t.Errorf("IPv4 row: %d %v", pid, ok)
	}
	if _, ok := findInWindowsTable(v4, afINET, net.ParseIP("127.0.0.1").To4(), 1); ok {
		t.Error("a port nobody has")
	}
	if _, ok := findInWindowsTable(v4[:10], afINET, net.ParseIP("127.0.0.1").To4(), 3128); ok {
		t.Error("a truncated table")
	}
	// IPv6: rows of local address, scope, local port, remote address, scope, remote port, state, pid
	v6 := make([]byte, 4+56)
	put(v6, 0, 1)
	copy(v6[4:], net.ParseIP("::1").To16())
	put(v6, 4+20, port(40000))
	put(v6, 4+52, 333)
	if pid, ok := findInWindowsTable(v6, afINET6, net.ParseIP("::1"), 40000); !ok || pid != 333 {
		t.Errorf("IPv6 row: %d %v", pid, ok)
	}
}

func TestParseLsofOwner(t *testing.T) {
	out := "p100\ncproxy\nn*:3128\nn127.0.0.1:3128->127.0.0.1:54321\np200\ncgit\nn127.0.0.1:54321->127.0.0.1:3128\n"
	pid, name, ok := parseLsofOwner(out, "127.0.0.1:54321")
	if !ok || pid != 200 || name != "git" {
		t.Errorf("owner = %d %q %v", pid, name, ok)
	}
	if _, _, ok := parseLsofOwner(out, "127.0.0.1:1"); ok {
		t.Error("a connection nobody has")
	}
	if pid, _, ok := parseLsofOwner("p300\ncnode\nn[::1]:50000->[::1]:3128\n", "[::1]:50000"); !ok || pid != 300 {
		t.Errorf("IPv6: %d %v", pid, ok)
	}
	if _, _, ok := parseLsofOwner("pabc\ncx\nn127.0.0.1:5->127.0.0.1:6\n", "127.0.0.1:5"); ok {
		t.Error("a process number that is not a number")
	}
}

func TestConnectionsAPIShowsTheClientProgram(t *testing.T) {
	old := clientProcessLookup
	t.Cleanup(func() { clientProcessLookup = old })
	clientProcessLookup = func(ip net.IP, port int) (*ClientProcess, error) {
		return &ClientProcess{PID: 77, Name: "curl", Exe: "/usr/bin/curl", Window: "Terminal", Cmdline: "curl https://example.org"}, nil
	}
	rec := connReg.newConn("connect", "127.0.0.1:40010", "example.org", "example.org:443", "", "Direct", "", "CONNECT", "")
	waitFor(t, "the process of the client", func() bool { return rec.snapshot().Process != nil })
	r := httptest.NewRequest("GET", "/api/connections", nil)
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, r)
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		if c["id"] == float64(rec.ID) {
			p, _ := c["process"].(map[string]any)
			if c["app"] != "Terminal" || p["name"] != "curl" || p["cmdline"] != "curl https://example.org" {
				t.Errorf("connection = %v", c)
			}
			return
		}
	}
	t.Error("the connection is not listed")
}
