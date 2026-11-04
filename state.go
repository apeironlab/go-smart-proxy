package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type ConnState string

const (
	StateConnecting     ConnState = "connecting"
	StateAuthenticating ConnState = "authenticating"
	StateAuthenticated  ConnState = "authenticated"
	StateEstablished    ConnState = "established"
	StateDone           ConnState = "done"
	StateFailed         ConnState = "failed"
	StateClosed         ConnState = "closed"
)

type ConnEvent struct {
	Time time.Time `json:"time"`
	Msg  string    `json:"msg"`
}

type connSnapshot struct {
	ID     uint64 `json:"id"`
	Type   string `json:"type"`
	Client string `json:"client,omitempty"`
	Host   string `json:"host,omitempty"`
	Target string `json:"target"`
	Proxy  string `json:"proxy,omitempty"`
	Route  string `json:"route,omitempty"`
	Cred   string `json:"cred,omitempty"`
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`

	State  ConnState `json:"state"`
	Auth   string    `json:"auth"`
	Status int       `json:"status,omitempty"`
	Error  string    `json:"error,omitempty"`

	Started time.Time  `json:"started"`
	Ended   *time.Time `json:"ended,omitempty"`

	BytesClientIn  int64 `json:"bytesClientIn"`
	BytesClientOut int64 `json:"bytesClientOut"`
	BytesUpIn      int64 `json:"bytesUpIn"`
	BytesUpOut     int64 `json:"bytesUpOut"`

	Events []ConnEvent `json:"events"`
}

// ConnInfo describes a live connection (tunnel, upstream transport
// connection or plain HTTP request) for the web UI.
type ConnInfo struct {
	ID     uint64
	Type   string
	Client string
	Host   string
	Target string
	Proxy  string
	Route  string
	Cred   string
	Method string
	URL    string

	State   ConnState
	Auth    string
	Status  int
	Error   string
	Started time.Time
	Ended   *time.Time

	bytesClientIn  atomic.Int64
	bytesClientOut atomic.Int64
	bytesUpIn      atomic.Int64
	bytesUpOut     atomic.Int64

	mu      sync.Mutex
	events  []ConnEvent
	closeFn func()
}

func (c *ConnInfo) setState(s ConnState) {
	c.mu.Lock()
	if c.State != s {
		c.State = s
		c.events = append(c.events, ConnEvent{Time: time.Now(), Msg: "state: " + string(s)})
	}
	c.mu.Unlock()
}

func (c *ConnInfo) event(msg string) {
	c.mu.Lock()
	if len(c.events) < 100 {
		c.events = append(c.events, ConnEvent{Time: time.Now(), Msg: msg})
	}
	c.mu.Unlock()
}

func (c *ConnInfo) setAuth(a string) {
	c.mu.Lock()
	c.Auth = a
	c.mu.Unlock()
}

func (c *ConnInfo) setError(msg string) {
	c.mu.Lock()
	c.Error = msg
	c.mu.Unlock()
}

func (c *ConnInfo) setStatus(code int) {
	c.mu.Lock()
	c.Status = code
	c.mu.Unlock()
}

func (c *ConnInfo) auth() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Auth
}

func (c *ConnInfo) state() ConnState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.State
}

func (c *ConnInfo) setRouting(route, proxy, cred string) {
	c.mu.Lock()
	c.Route = route
	c.Proxy = proxy
	c.Cred = cred
	c.mu.Unlock()
}

func (c *ConnInfo) setCloseFn(fn func()) {
	c.mu.Lock()
	c.closeFn = fn
	c.mu.Unlock()
}

func (c *ConnInfo) finish(state ConnState) {
	c.mu.Lock()
	if c.Ended == nil {
		now := time.Now()
		c.Ended = &now
		c.State = state
		c.events = append(c.events, ConnEvent{Time: now, Msg: "state: " + string(state)})
	}
	c.mu.Unlock()
}

func (c *ConnInfo) snapshot() connSnapshot {
	c.mu.Lock()
	s := connSnapshot{
		ID: c.ID, Type: c.Type, Client: c.Client, Host: c.Host, Target: c.Target,
		Proxy: c.Proxy, Route: c.Route, Cred: c.Cred, Method: c.Method, URL: c.URL,
		State: c.State, Auth: c.Auth, Status: c.Status, Error: c.Error,
		Started: c.Started, Ended: c.Ended,
		BytesClientIn:  c.bytesClientIn.Load(),
		BytesClientOut: c.bytesClientOut.Load(),
		BytesUpIn:      c.bytesUpIn.Load(),
		BytesUpOut:     c.bytesUpOut.Load(),
		Events:         append([]ConnEvent(nil), c.events...),
	}
	c.mu.Unlock()
	return s
}

type connRegistry struct {
	mu      sync.Mutex
	nextID  uint64
	records map[uint64]*ConnInfo
}

var connReg = &connRegistry{records: make(map[uint64]*ConnInfo)}

func (r *connRegistry) newConn(typ, client, host, target, proxyAddr, route, cred, method, url string) *ConnInfo {
	r.mu.Lock()
	r.nextID++
	rec := &ConnInfo{
		ID:      r.nextID,
		Type:    typ,
		Client:  client,
		Host:    host,
		Target:  target,
		Proxy:   proxyAddr,
		Route:   route,
		Cred:    cred,
		Method:  method,
		URL:     url,
		State:   StateConnecting,
		Auth:    "none",
		Started: time.Now(),
	}
	r.records[rec.ID] = rec
	r.mu.Unlock()
	return rec
}

func (r *connRegistry) get(id uint64) *ConnInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.records[id]
}

func (r *connRegistry) close(id uint64) bool {
	r.mu.Lock()
	rec := r.records[id]
	r.mu.Unlock()
	if rec == nil {
		return false
	}
	rec.mu.Lock()
	fn := rec.closeFn
	rec.mu.Unlock()
	if fn != nil {
		fn()
	}
	return true
}

func (r *connRegistry) activeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, rec := range r.records {
		rec.mu.Lock()
		if rec.Ended == nil {
			n++
		}
		rec.mu.Unlock()
	}
	return n
}

// list returns snapshots of all connections; closed connections older than
// 10 minutes are pruned.
func (r *connRegistry) list(includeClosed bool) []connSnapshot {
	r.mu.Lock()
	cutoff := time.Now().Add(-10 * time.Minute)
	var prune []uint64
	for id, rec := range r.records {
		rec.mu.Lock()
		old := rec.Ended != nil && rec.Ended.Before(cutoff)
		rec.mu.Unlock()
		if old {
			prune = append(prune, id)
		}
	}
	for _, id := range prune {
		delete(r.records, id)
	}

	snaps := make([]connSnapshot, 0, len(r.records))
	for _, rec := range r.records {
		rec.mu.Lock()
		ended := rec.Ended == nil
		rec.mu.Unlock()
		if ended || includeClosed {
			snaps = append(snaps, rec.snapshot())
		}
	}
	r.mu.Unlock()
	// Stable order: oldest first, so rows in the UI do not jump around.
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].ID < snaps[j].ID })
	return snaps
}

// countingConn counts bytes read from and written to an underlying
// connection. Reads increment "in", writes increment "out".
type countingConn struct {
	net.Conn
	in  *atomic.Int64
	out *atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.in.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.out.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

type countingReadCloser struct {
	io.ReadCloser
	counter *atomic.Int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.counter.Add(int64(n))
	}
	return n, err
}

// countingReader counts bytes read from an underlying reader. It is used for
// the client side of tunnels, where data is read through a bufio.Reader that
// wraps the raw connection and therefore bypasses countingConn.Read.
type countingReader struct {
	io.Reader
	counter *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	if n > 0 {
		c.counter.Add(int64(n))
	}
	return n, err
}

type countingResponseWriter struct {
	http.ResponseWriter
	counter *atomic.Int64
	status  int
}

func (w *countingResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	if n > 0 {
		w.counter.Add(int64(n))
	}
	return n, err
}

func (w *countingResponseWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *countingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *countingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}

// connRecKey is the context key used to attach a *ConnInfo to a request.
type connRecKey struct{}

// parseConnID parses the numeric connection id from a URL path segment.
func parseConnID(s string) (uint64, bool) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}
