package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// GatewayConfig configures an application gateway.
type GatewayConfig struct {
	// Address is the relay's mTLS address, host:port.
	Address string
	// CertFile and KeyFile are the gateway's service certificate (see
	// IssueGateway or the management interface); CAFile is the CA that signed
	// the relay's server certificate.
	CertFile, KeyFile, CAFile string
	// ServerName overrides the name checked in the relay's certificate (default:
	// the host of Address).
	ServerName string
	Logger     *log.Logger
}

// Gateway connects to the relay and opens the applications it is told to
// serve. It only ever connects to the targets of the catalog it received, never
// to anything a user asks for.
type Gateway struct {
	cfg GatewayConfig
	log *log.Logger

	mu   sync.Mutex
	apps map[string]GatewayApp
}

// NewGateway prepares an application gateway: it loads the certificate and the
// CA but does not connect until Run.
func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	if cfg.Address == "" {
		return nil, errors.New("gateway: the relay address is required")
	}
	g := &Gateway{cfg: cfg, log: cfg.Logger, apps: map[string]GatewayApp{}}
	if g.log == nil {
		g.log = log.Default()
	}
	if _, err := g.tlsConfig(); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *Gateway) tlsConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(g.cfg.CertFile, g.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("gateway certificate: %w", err)
	}
	pool, err := LoadPool(g.cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("relay CA: %w", err)
	}
	name := g.cfg.ServerName
	if name == "" {
		name, _, _ = net.SplitHostPort(g.cfg.Address)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12}, nil
}

// Run connects and serves until ctx ends, reconnecting after failures.
func (g *Gateway) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		started := time.Now()
		err := g.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		g.log.Printf("gateway: disconnected from the relay: %v (retrying in %s)", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (g *Gateway) runOnce(ctx context.Context) error {
	cfg, err := g.tlsConfig() // re-read: certificates get renewed
	if err != nil {
		return err
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	raw, err := (&tls.Dialer{NetDialer: d, Config: cfg}).DialContext(ctx, "tcp", g.cfg.Address)
	if err != nil {
		return err
	}
	yc := yamux.DefaultConfig()
	yc.LogOutput = io.Discard
	sess, err := yamux.Client(raw, yc)
	if err != nil {
		raw.Close()
		return err
	}
	defer sess.Close()
	go func() {
		<-ctx.Done()
		sess.Close()
	}()

	ctrl, err := sess.OpenStream()
	if err != nil {
		return err
	}
	if err := WriteLine(ctrl, DialReq{T: TGateway}); err != nil {
		return err
	}
	g.log.Printf("gateway: connected to %s", g.cfg.Address)
	go func() {
		for {
			st, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go g.handleStream(st)
		}
	}()
	br := NewReader(ctrl)
	for {
		var st GatewayState
		if err := ReadLine(br, &st); err != nil {
			return err
		}
		if st.T != TGatewayState {
			continue
		}
		apps := map[string]GatewayApp{}
		for _, a := range st.Apps {
			apps[a.ID] = a
		}
		g.mu.Lock()
		g.apps = apps
		g.mu.Unlock()
		g.log.Printf("gateway: serving %d application(s)", len(apps))
	}
}

// Apps returns the applications currently served.
func (g *Gateway) Apps() []GatewayApp {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]GatewayApp, 0, len(g.apps))
	for _, a := range g.apps {
		out = append(out, a)
	}
	return out
}

func (g *Gateway) handleStream(st net.Conn) {
	br := NewReader(st)
	st.SetReadDeadline(time.Now().Add(firstLineTimeout))
	var req DialReq
	if err := ReadLine(br, &req); err != nil || req.T != TDial {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	reply := func(r DialResp) { WriteLine(st, r) }

	g.mu.Lock()
	app, ok := g.apps[req.App]
	g.mu.Unlock()
	if !ok {
		reply(DialResp{Error: "unknown application"})
		st.Close()
		return
	}
	switch app.Kind {
	case "http":
		if err := reply2(st, DialResp{OK: true}); err != nil {
			st.Close()
			return
		}
		g.serveHTTP(&readerConn{Conn: st, r: br}, app)
	default:
		backend, err := net.DialTimeout("tcp", app.Target, 10*time.Second)
		if err != nil {
			g.log.Printf("gateway: %s: %s: %v", app.ID, app.Target, err)
			reply(DialResp{Error: "backend unreachable"})
			st.Close()
			return
		}
		if err := reply2(st, DialResp{OK: true}); err != nil {
			backend.Close()
			st.Close()
			return
		}
		g.log.Printf("gateway: %s opened %s", req.From, app.ID)
		Pipe(st, br, backend, bufio.NewReader(backend))
	}
}

func reply2(w io.Writer, r DialResp) error { return WriteLine(w, r) }

// readerConn reads through r, which may hold bytes already buffered.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// serveHTTP is the reverse proxy of an http application, serving the one
// connection of this stream. It makes the backend think it is reached under its
// own name: Host, Origin and Referer are rewritten to the backend, and
// Location and cookie domains of the answers back to the name the user used.
func (g *Gateway) serveHTTP(conn net.Conn, app GatewayApp) {
	target, err := url.Parse(app.Target)
	if err != nil {
		conn.Close()
		return
	}
	pub := app.Host
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			for k, v := range app.SetHeaders {
				r.Out.Header.Set(k, v)
			}
			// Do not pass on what a user could use to claim an identity.
			r.Out.Header.Del("X-Forwarded-For")
			for _, h := range []string{"Origin", "Referer"} {
				if v := r.In.Header.Get(h); v != "" {
					r.Out.Header.Set(h, rewriteOrigin(v, pub, target))
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if loc := resp.Header.Get("Location"); loc != "" {
				resp.Header.Set("Location", rewriteLocation(loc, target, pub))
			}
			if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
				resp.Header.Del("Set-Cookie")
				for _, c := range cookies {
					resp.Header.Add("Set-Cookie", stripCookieDomain(c))
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.log.Printf("gateway: %s: %v", app.ID, err)
			http.Error(w, "the application cannot be reached", http.StatusBadGateway)
		},
	}
	l := newOneConnListener(conn)
	srv := &http.Server{
		Handler:           rp,
		ReadHeaderTimeout: 30 * time.Second,
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				l.Close()
			}
		},
	}
	srv.Serve(l)
}

func rewriteOrigin(v, pub string, target *url.URL) string {
	u, err := url.Parse(v)
	if err != nil || !strings.EqualFold(u.Hostname(), pub) {
		return v
	}
	u.Scheme, u.Host = target.Scheme, target.Host
	return u.String()
}

func rewriteLocation(loc string, target *url.URL, pub string) string {
	u, err := url.Parse(loc)
	if err != nil || !u.IsAbs() {
		return loc
	}
	if strings.EqualFold(u.Host, target.Host) {
		u.Scheme, u.Host = "http", pub
		return u.String()
	}
	return loc
}

// stripCookieDomain drops the Domain attribute: the browser then keeps the
// cookie for the name it used, whatever the backend believes its name is.
func stripCookieDomain(c string) string {
	parts := strings.Split(c, ";")
	out := parts[:0]
	for i, p := range parts {
		if i > 0 && strings.HasPrefix(strings.ToLower(strings.TrimSpace(p)), "domain=") {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, ";")
}

// oneConnListener hands out a single connection, then waits to be closed.
type oneConnListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{ch: make(chan net.Conn, 1), done: make(chan struct{})}
	l.ch <- c
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return &net.TCPAddr{} }
