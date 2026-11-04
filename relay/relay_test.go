package relay

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

type testClient struct {
	email string
	ys    *yamux.Session
	ctrl  net.Conn
	br    *bufio.Reader
}

func connectTestClient(t *testing.T, addr string, pool *x509.CertPool, cert tls.Certificate, email, device string) *testClient {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	ys, err := yamux.Client(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctrl, _ := ys.OpenStream()
	WriteLine(ctrl, DialReq{T: TControl, Device: device})
	tcl := &testClient{email: email, ys: ys, ctrl: ctrl, br: NewReader(ctrl)}
	t.Cleanup(func() { ys.Close() })
	return tcl
}

// connectTestClientWithHello is connectTestClient with a custom control hello.
func connectTestClientWithHello(t *testing.T, addr string, pool *x509.CertPool, cert tls.Certificate, email string, hello DialReq) *testClient {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	ys, err := yamux.Client(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctrl, _ := ys.OpenStream()
	WriteLine(ctrl, hello)
	tcl := &testClient{email: email, ys: ys, ctrl: ctrl, br: NewReader(ctrl)}
	t.Cleanup(func() { ys.Close() })
	return tcl
}

func setup(t *testing.T, emails ...string) (addr string, clients []*testClient) {
	addr, _, _, clients = setupWithDir(t, emails...)
	return addr, clients
}

func setupWithDir(t *testing.T, emails ...string) (addr, dir string, pool *x509.CertPool, clients []*testClient) {
	t.Helper()
	dir = t.TempDir()
	ca := filepath.Join(dir, "ca")
	if err := InitCA(ca); err != nil {
		t.Fatal(err)
	}
	if err := IssueServer(ca, filepath.Join(dir, "srv"), []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := TLSConfig(filepath.Join(dir, "srv", "server.pem"), filepath.Join(dir, "srv", "server-key.pem"), filepath.Join(ca, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := NewStore("")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go NewServer(store).Serve(ln)
	pool, _ = LoadPool(filepath.Join(ca, "ca.pem"))

	for _, e := range emails {
		out := filepath.Join(dir, e)
		if err := IssueClient(ca, out, e); err != nil {
			t.Fatal(err)
		}
		cert, err := tls.LoadX509KeyPair(filepath.Join(out, "client.pem"), filepath.Join(out, "client-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, connectTestClient(t, ln.Addr().String(), pool, cert, e, ""))
	}
	return ln.Addr().String(), dir, pool, clients
}

func (c *testClient) state(t *testing.T) State {
	var st State
	c.ctrl.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := ReadLine(c.br, &st); err != nil {
		t.Fatalf("%s: read state: %v", c.email, err)
	}
	return st
}

// waitState reads states until cond is true.
func (c *testClient) waitState(t *testing.T, cond func(State) bool) State {
	for i := 0; i < 20; i++ {
		if st := c.state(t); cond(st) {
			return st
		}
	}
	t.Fatalf("%s: condition never met", c.email)
	return State{}
}

func TestContactsAndDial(t *testing.T) {
	_, cl := setup(t, "alice@example.com", "bob@example.com")
	alice, bob := cl[0], cl[1]

	// the CA only trusts our certificates: identities come from the e-mail SAN
	WriteLine(alice.ctrl, ClientMsg{T: TContactRequest, Email: "Bob@Example.com"})
	bob.waitState(t, func(s State) bool { return len(s.Incoming) == 1 && s.Incoming[0] == "alice@example.com" })

	// before approval alice cannot dial through bob
	st, _ := alice.ys.OpenStream()
	WriteLine(st, DialReq{T: TDial, Via: "bob@example.com", Target: "127.0.0.1:9"})
	var resp DialResp
	if err := ReadLine(NewReader(st), &resp); err != nil || resp.OK {
		t.Fatalf("expected refusal, got %+v err=%v", resp, err)
	}

	WriteLine(bob.ctrl, ClientMsg{T: TContactRespond, Email: "alice@example.com", Accept: true})
	alice.waitState(t, func(s State) bool { return len(s.Contacts) == 1 && s.Contacts[0].Online })
	bob.waitState(t, func(s State) bool { return len(s.Contacts) == 1 && len(s.Incoming) == 0 })

	// bob serves dial requests: echo
	go func() {
		for {
			s, err := bob.ys.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				br := NewReader(s)
				var req DialReq
				if ReadLine(br, &req) != nil || req.From != "alice@example.com" || req.Target != "10.1.2.3:80" {
					s.Close()
					return
				}
				WriteLine(s, DialResp{OK: true})
				io.Copy(s, br)
				s.Close()
			}()
		}
	}()

	st, _ = alice.ys.OpenStream()
	WriteLine(st, DialReq{T: TDial, Via: "bob@example.com", Target: "10.1.2.3:80"})
	br := NewReader(st)
	if err := ReadLine(br, &resp); err != nil || !resp.OK {
		t.Fatalf("dial failed: %+v %v", resp, err)
	}
	io.WriteString(st, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo got %q err=%v", buf, err)
	}

	// removing the contact revokes access
	WriteLine(bob.ctrl, ClientMsg{T: TContactRemove, Email: "alice@example.com"})
	alice.waitState(t, func(s State) bool { return len(s.Contacts) == 0 })
	st, _ = alice.ys.OpenStream()
	WriteLine(st, DialReq{T: TDial, Via: "bob@example.com", Target: "10.1.2.3:80"})
	if err := ReadLine(NewReader(st), &resp); err != nil || resp.OK {
		t.Fatalf("expected refusal after removal, got %+v", resp)
	}
}

func TestMultipleDevices(t *testing.T) {
	addr, dir, pool, cl := setupWithDir(t, "alice@example.com", "bob@example.com")
	alice, bobDefault := cl[0], cl[1]

	bobCert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "bob@example.com", "client.pem"),
		filepath.Join(dir, "bob@example.com", "client-key.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}
	bobDesktop := connectTestClient(t, addr, pool, bobCert, "bob@example.com", "desktop")

	// Bob sees both of his devices, without establishing a contact with himself.
	my := bobDefault.waitState(t, func(s State) bool { return len(s.MyDevices) == 2 })
	if my.MyDevices[0].ID != "default" || my.MyDevices[0].Online != true ||
		my.MyDevices[1].ID != "desktop" || my.MyDevices[1].Online != true {
		t.Fatalf("unexpected own devices: %+v", my.MyDevices)
	}

	// Establish the contact.
	WriteLine(alice.ctrl, ClientMsg{T: TContactRequest, Email: "bob@example.com"})
	bobDefault.waitState(t, func(s State) bool { return len(s.Incoming) == 1 })
	WriteLine(bobDefault.ctrl, ClientMsg{T: TContactRespond, Email: "alice@example.com", Accept: true})
	st := alice.waitState(t, func(s State) bool {
		return len(s.Contacts) == 1 && len(s.Contacts[0].Devices) == 2
	})
	if st.Contacts[0].Devices[0] != "default" || st.Contacts[0].Devices[1] != "desktop" {
		t.Fatalf("unexpected devices: %v", st.Contacts[0].Devices)
	}

	// The desktop session serves dial requests.
	go func() {
		for {
			s, err := bobDesktop.ys.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				br := NewReader(s)
				var req DialReq
				if ReadLine(br, &req) != nil ||
					(req.From != "alice@example.com" && req.From != "bob@example.com") {
					s.Close()
					return
				}
				WriteLine(s, DialResp{OK: true})
				io.Copy(s, br)
				s.Close()
			}()
		}
	}()

	// An explicit device reaches that device only.
	st1, _ := alice.ys.OpenStream()
	WriteLine(st1, DialReq{T: TDial, Via: "bob@example.com", ViaDevice: "desktop", Target: "10.1.2.3:80"})
	var resp DialResp
	if err := ReadLine(NewReader(st1), &resp); err != nil || !resp.OK {
		t.Fatalf("dial to desktop failed: %+v err=%v", resp, err)
	}
	st1.Close()

	// A user can use another one of their devices directly, without a contact
	// request between themselves.
	stSelf, _ := bobDefault.ys.OpenStream()
	WriteLine(stSelf, DialReq{T: TDial, Via: "bob@example.com", ViaDevice: "desktop", Target: "10.1.2.3:80"})
	if err := ReadLine(NewReader(stSelf), &resp); err != nil || !resp.OK {
		t.Fatalf("self-device dial failed: %+v err=%v", resp, err)
	}
	stSelf.Close()

	// Without a device, two online devices are ambiguous and must not be
	// chosen by chance.
	st2, _ := alice.ys.OpenStream()
	WriteLine(st2, DialReq{T: TDial, Via: "bob@example.com", Target: "10.1.2.3:80"})
	if err := ReadLine(NewReader(st2), &resp); err != nil || resp.OK {
		t.Fatalf("ambiguous dial must fail, got %+v err=%v", resp, err)
	}
	st2.Close()
}

func TestClientWithoutCertificateRejected(t *testing.T) {
	addr, _ := setup(t)
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		// TLS 1.3 reports the missing certificate on first I/O
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Read(make([]byte, 1))
		c.Close()
	}
	if err == nil {
		t.Fatal("connection without client certificate must fail")
	}
}
