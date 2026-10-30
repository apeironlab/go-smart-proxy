package relay

import (
	"bufio"
	"crypto/tls"
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

func setup(t *testing.T, emails ...string) (addr string, clients []*testClient) {
	dir := t.TempDir()
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
	pool, _ := LoadPool(filepath.Join(ca, "ca.pem"))

	for _, e := range emails {
		out := filepath.Join(dir, e)
		if err := IssueClient(ca, out, e); err != nil {
			t.Fatal(err)
		}
		cert, err := tls.LoadX509KeyPair(filepath.Join(out, "client.pem"), filepath.Join(out, "client-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool})
		if err != nil {
			t.Fatal(err)
		}
		ys, err := yamux.Client(c, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctrl, _ := ys.OpenStream()
		WriteLine(ctrl, DialReq{T: TControl})
		tcl := &testClient{email: e, ys: ys, ctrl: ctrl, br: NewReader(ctrl)}
		t.Cleanup(func() { ys.Close() })
		clients = append(clients, tcl)
	}
	return ln.Addr().String(), clients
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
