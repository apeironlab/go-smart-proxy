package blocklist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Source is a list to download.
type Source struct {
	ID     string // names the cache file together with the URL
	Name   string
	URL    string
	Format Format
}

// CheckURL accepts only plain http(s) addresses with no credentials.
func CheckURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("the address of a list must be an http:// or https:// URL")
	}
	return nil
}

// MaxListBytes bounds a download.
const MaxListBytes = 128 << 20

// Fetcher downloads lists and keeps them in Dir, so that they are available at
// start-up and when the network is not.
type Fetcher struct {
	Dir string
	// DenyPrivate refuses to connect to private, loopback and link-local
	// addresses: for a server that fetches URLs an administrator typed, so that
	// it cannot be pointed at its own network.
	DenyPrivate bool
	Client      *http.Client
	// Proxy chooses the proxy for a request (default: the environment's).
	Proxy func(*http.Request) (*url.URL, error)
}

type cacheMeta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"lastModified,omitempty"`
	Fetched      time.Time `json:"fetched"`
}

func (f *Fetcher) path(s Source) string {
	sum := sha256.Sum256([]byte(s.URL))
	return filepath.Join(f.Dir, hex.EncodeToString(sum[:8]))
}

// isPrivate reports whether an address is one a fetcher with DenyPrivate must
// not reach.
func isPrivate(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast()
}

// checkPublic refuses a host that names (or resolves to) a private address. It
// is the check that works when a proxy does the connecting; without a proxy
// the dialer's own check, made on the address actually used, is the stronger
// one.
func checkPublic(ctx context.Context, host string) error {
	if a, err := netip.ParseAddr(host); err == nil {
		if isPrivate(a) {
			return errors.New("refusing to connect to a private address")
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil // the connection will fail with the real reason
	}
	for _, a := range ips {
		if isPrivate(a) {
			return errors.New("refusing to connect to a private address")
		}
	}
	return nil
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	plain := &net.Dialer{Timeout: 20 * time.Second}
	guarded := &net.Dialer{Timeout: 20 * time.Second}
	if f.DenyPrivate {
		guarded.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if a, err := netip.ParseAddr(host); err == nil && isPrivate(a) {
				return errors.New("refusing to connect to a private address")
			}
			return nil
		}
	}
	// A proxy named in the environment is the operator's choice: it may well be
	// on a private address. Connections to it are not restricted; what is
	// asked of it is (see Update).
	var mu sync.Mutex
	proxies := map[string]bool{}
	return &http.Client{
		Timeout: 3 * time.Minute,
		Transport: &http.Transport{
			Proxy: func(r *http.Request) (*url.URL, error) {
				proxyFn := f.Proxy
				if proxyFn == nil {
					proxyFn = http.ProxyFromEnvironment
				}
				u, err := proxyFn(r)
				if u != nil {
					host := u.Host
					if u.Port() == "" {
						port := map[string]string{"http": "80", "https": "443", "socks5": "1080"}[u.Scheme]
						host = net.JoinHostPort(u.Hostname(), port)
					}
					mu.Lock()
					proxies[host] = true
					mu.Unlock()
				}
				return u, err
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				mu.Lock()
				viaProxy := proxies[addr]
				mu.Unlock()
				if viaProxy {
					return plain.DialContext(ctx, network, addr)
				}
				return guarded.DialContext(ctx, network, addr)
			},
			TLSHandshakeTimeout: 15 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if err := CheckURL(req.URL.String()); err != nil {
				return err
			}
			if f.DenyPrivate {
				return checkPublic(req.Context(), req.URL.Hostname())
			}
			return nil
		},
	}
}

// Update downloads the list if it changed. It returns whether the cache was
// replaced. A failure leaves the previous copy in place.
func (f *Fetcher) Update(ctx context.Context, s Source) (bool, error) {
	if err := CheckURL(s.URL); err != nil {
		return false, err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return false, err
	}
	base := f.path(s)
	var meta cacheMeta
	if b, err := os.ReadFile(base + ".json"); err == nil {
		json.Unmarshal(b, &meta)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return false, err
	}
	if f.DenyPrivate {
		if err := checkPublic(ctx, req.URL.Hostname()); err != nil {
			return false, err
		}
	}
	req.Header.Set("User-Agent", "go-smart-proxy-blocklist")
	if _, err := os.Stat(base + ".list"); err == nil && meta.URL == s.URL {
		if meta.ETag != "" {
			req.Header.Set("If-None-Match", meta.ETag)
		}
		if meta.LastModified != "" {
			req.Header.Set("If-Modified-Since", meta.LastModified)
		}
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		meta.Fetched = time.Now()
		writeMeta(base, meta)
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("%s answered %s", s.URL, resp.Status)
	}
	tmp, err := os.CreateTemp(f.Dir, "dl-*.tmp")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, MaxListBytes+1))
	tmp.Close()
	if err != nil {
		return false, err
	}
	if n > MaxListBytes {
		return false, errors.New("the list is too large")
	}
	// Make sure it parses before it replaces a good copy.
	fh, err := os.Open(tmp.Name())
	if err != nil {
		return false, err
	}
	d, nets, perr := Parse(fh, s.Format)
	fh.Close()
	if perr != nil {
		return false, perr
	}
	if len(d)+len(nets) == 0 {
		return false, errors.New("the list has no usable entries (wrong format or address?)")
	}
	if err := os.Rename(tmp.Name(), base+".list"); err != nil {
		return false, err
	}
	writeMeta(base, cacheMeta{URL: s.URL, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), Fetched: time.Now()})
	return true, nil
}

func writeMeta(base string, m cacheMeta) {
	b, _ := json.Marshal(m)
	os.WriteFile(base+".json", b, 0o600)
}

// Load reads the cached copy of a list. fetched is when it was last checked.
func (f *Fetcher) Load(s Source) (domains []string, nets []netip.Prefix, fetched time.Time, err error) {
	base := f.path(s)
	fh, err := os.Open(base + ".list")
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	defer fh.Close()
	domains, nets, err = Parse(fh, s.Format)
	var meta cacheMeta
	if b, rerr := os.ReadFile(base + ".json"); rerr == nil {
		json.Unmarshal(b, &meta)
	}
	return domains, nets, meta.Fetched, err
}

// Remove deletes the cached copy of a list nobody uses any more.
func (f *Fetcher) Remove(s Source) {
	base := f.path(s)
	os.Remove(base + ".list")
	os.Remove(base + ".json")
}
