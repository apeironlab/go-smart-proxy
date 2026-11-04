// Package relay implements the rendezvous relay used to reach the network of
// another user: clients connect to the relay with mutual TLS, the relay keeps
// the address book (contacts approved by both sides) and splices streams
// between a requesting client and the contact that will open the connection.
package relay

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// Message types on the control stream and on dial streams.
const (
	TControl        = "control"         // first line on the control stream (client -> relay)
	TDial           = "dial"            // first line on a dial stream
	TPing           = "ping"            // first line on a ping stream: reachability and latency probe
	TState          = "state"           // relay -> client: full state snapshot
	TContactRequest = "contact_request" // client -> relay
	TContactRespond = "contact_respond" // client -> relay
	TContactRemove  = "contact_remove"  // client -> relay
	TContext        = "context"         // client -> relay: the network context this device shares
	TGateway        = "gateway"         // first line of an application gateway's control stream
	TGatewayState   = "gwstate"         // relay -> gateway: the applications it serves
)

// NetContext is what a device chooses to tell its contacts about the network
// it is on: a label picked by the user (for instance "office-vpn") and whether
// a VPN is active. It is self-declared and informational: it helps a contact
// decide whether a device is the right exit, it is not a security boundary.
// No addresses, host names or domains are part of it.
type NetContext struct {
	Label string `json:"label,omitempty"`
	VPN   bool   `json:"vpn,omitempty"`
}

// MaxLabelLen bounds a context label.
const MaxLabelLen = 40

// SanitizeContext normalizes a context received from a client: control
// characters are removed, the label is trimmed and shortened. A nil context
// (the device shares nothing) stays nil.
func SanitizeContext(c *NetContext) *NetContext {
	if c == nil {
		return nil
	}
	var b strings.Builder
	for _, r := range strings.TrimSpace(c.Label) {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= MaxLabelLen {
			break
		}
	}
	return &NetContext{Label: strings.TrimSpace(b.String()), VPN: c.VPN}
}

// ClientMsg is a command sent by a client on the control stream.
type ClientMsg struct {
	T       string      `json:"t"`
	Email   string      `json:"email,omitempty"`
	Accept  bool        `json:"accept,omitempty"`
	Context *NetContext `json:"context,omitempty"` // TContext
}

// Contact is an entry of the address book.
type Contact struct {
	Email   string   `json:"email"`
	Online  bool     `json:"online"`
	Devices []string `json:"devices,omitempty"` // online devices of the contact
	// LastSeen is when the contact was last online (Unix seconds), set only
	// while it is offline and was seen at least once.
	LastSeen int64 `json:"lastSeen,omitempty"`
	// Context holds what each online device shares about its network, by
	// device code. A device missing from the map shares nothing.
	Context map[string]NetContext `json:"context,omitempty"`
}

// DeviceInfo describes one of the user's own devices.
type DeviceInfo struct {
	ID      string      `json:"id"`
	Online  bool        `json:"online"`
	Context *NetContext `json:"context,omitempty"`
}

// State is the snapshot of a client's address book pushed by the relay.
type State struct {
	T         string       `json:"t"`
	Email     string       `json:"email"`
	Contacts  []Contact    `json:"contacts"`
	MyDevices []DeviceInfo `json:"myDevices,omitempty"`
	// Apps is the catalog of applications this user may open.
	Apps     []AppInfo `json:"apps,omitempty"`
	Incoming []string  `json:"incoming"` // requests waiting for our answer
	Outgoing []string  `json:"outgoing"` // requests we sent, not answered yet
	Notice   string    `json:"notice,omitempty"`
}

// DialReq opens a stream to Target through contact Via (client -> relay) or
// asks the contact to dial it on behalf of From (relay -> contact).
type DialReq struct {
	T          string `json:"t"`
	Via        string `json:"via,omitempty"`
	ViaDevice  string `json:"viaDevice,omitempty"` // specific device of the contact
	From       string `json:"from,omitempty"`
	FromDevice string `json:"fromDevice,omitempty"` // device of the requester
	Device     string `json:"device,omitempty"`     // control stream: this client's device
	Target     string `json:"target"`
	// App, on a dial, names a catalog application instead of a contact: the
	// relay checks the user may open it and routes to its gateway. Via and
	// Target are then ignored.
	App string `json:"app,omitempty"`
	// Context, on the control stream hello, is the network context the device
	// shares from the start (nil: nothing).
	Context *NetContext `json:"context,omitempty"`
}

// DialResp is the answer to a DialReq.
type DialResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// WriteLine writes v as a single JSON line.
func WriteLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadLine reads one JSON line (max 8 KiB) into v.
func ReadLine(br *bufio.Reader, v any) error {
	line, err := br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return errors.New("message too long")
		}
		return err
	}
	return json.Unmarshal(line, v)
}

// NewReader returns a buffered reader sized for control messages.
func NewReader(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, 8192) }

// NormalizeEmail lowercases and validates an e-mail address.
func NormalizeEmail(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	// Exactly one '@': addresses such as "a@evil.com@allowed.com" are parsed
	// differently by different components (domain filter, SMTP server), which
	// would let a request slip past the allowed-domain list.
	at := strings.IndexByte(s, '@')
	if at <= 0 || at != strings.LastIndexByte(s, '@') || at == len(s)-1 || len(s) > 254 {
		return "", false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune(",;:<>\"()[]\\", r) {
			return "", false
		}
	}
	return s, true
}

// NormalizeDevice validates a device code. An empty string means "not
// specified" and is valid.
func NormalizeDevice(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", true
	}
	if len(s) > 40 || s[0] == '-' || s[len(s)-1] == '-' {
		return "", false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return "", false
	}
	return s, true
}

// EmailFromCert returns the identity of a client certificate: its first e-mail SAN.
func EmailFromCert(c *x509.Certificate) (string, bool) {
	for _, e := range c.EmailAddresses {
		if v, ok := NormalizeEmail(e); ok {
			return v, true
		}
	}
	return "", false
}

type closeWriter interface{ CloseWrite() error }

// Pipe splices a and b until both directions end. aR and bR are the readers
// (possibly buffered) for a and b.
func Pipe(a net.Conn, aR io.Reader, b net.Conn, bR io.Reader) {
	done := make(chan struct{}, 2)
	cp := func(dst net.Conn, src io.Reader) {
		io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.SetReadDeadline(time.Now())
		}
		done <- struct{}{}
	}
	go cp(b, aR)
	go cp(a, bR)
	<-done
	<-done
	a.Close()
	b.Close()
}
