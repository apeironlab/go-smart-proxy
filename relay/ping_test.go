package relay

import (
	"path/filepath"
	"testing"
	"time"
)

func ping(t *testing.T, c *testClient, via, device string) DialResp {
	t.Helper()
	st, err := c.ys.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	WriteLine(st, DialReq{T: TPing, Via: via, ViaDevice: device})
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	var resp DialResp
	if err := ReadLine(NewReader(st), &resp); err != nil {
		t.Fatalf("ping read: %v", err)
	}
	return resp
}

// serveProbes makes the test client answer pings (like the real client does)
// and records who asked.
func serveProbes(t *testing.T, c *testClient, from chan<- string) {
	go func() {
		for {
			s, err := c.ys.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				defer s.Close()
				var req DialReq
				if ReadLine(NewReader(s), &req) != nil || req.T != TPing {
					return
				}
				if from != nil {
					from <- req.From
				}
				WriteLine(s, DialResp{OK: true})
			}()
		}
	}()
}

func befriend(t *testing.T, a, b *testClient) {
	t.Helper()
	WriteLine(a.ctrl, ClientMsg{T: TContactRequest, Email: b.email})
	b.waitState(t, func(s State) bool { return len(s.Incoming) == 1 })
	WriteLine(b.ctrl, ClientMsg{T: TContactRespond, Email: a.email, Accept: true})
	a.waitState(t, func(s State) bool { return len(s.Contacts) == 1 && s.Contacts[0].Online })
}

func TestPingRelayItself(t *testing.T) {
	_, cl := setup(t, "alice@example.com")
	if r := ping(t, cl[0], "", ""); !r.OK {
		t.Fatalf("relay ping: %+v", r)
	}
}

func TestPingContact(t *testing.T) {
	_, cl := setup(t, "alice@example.com", "bob@example.com")
	alice, bob := cl[0], cl[1]
	befriend(t, alice, bob)
	from := make(chan string, 1)
	serveProbes(t, bob, from)

	if r := ping(t, alice, "bob@example.com", ""); !r.OK {
		t.Fatalf("ping through the contact: %+v", r)
	}
	select {
	case who := <-from:
		if who != "alice@example.com" {
			t.Fatalf("the contact must learn who asked, got %q", who)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the contact's device never received the probe")
	}
}

func TestPingRefusals(t *testing.T) {
	_, cl := setup(t, "alice@example.com", "bob@example.com", "carol@example.com")
	alice, bob := cl[0], cl[1]
	serveProbes(t, bob, nil)

	// not a contact yet: nothing is revealed about bob's presence
	if r := ping(t, alice, "bob@example.com", ""); r.OK || r.Error == "" {
		t.Fatalf("a stranger must not be able to probe: %+v", r)
	}
	// own device: the device being used cannot be probed through the relay
	if r := ping(t, alice, "alice@example.com", ""); r.OK {
		t.Fatalf("probing yourself must be refused: %+v", r)
	}
	// malformed address
	if r := ping(t, alice, "not an email", ""); r.OK {
		t.Fatalf("invalid address: %+v", r)
	}
}

func TestPingOfflineAndOldClients(t *testing.T) {
	_, cl := setup(t, "alice@example.com", "bob@example.com")
	alice, bob := cl[0], cl[1]
	befriend(t, alice, bob)

	// bob runs an old client that closes streams it does not understand
	go func() {
		for {
			s, err := bob.ys.AcceptStream()
			if err != nil {
				return
			}
			s.Close()
		}
	}()
	start := time.Now()
	r := ping(t, alice, "bob@example.com", "")
	if r.OK || r.Error == "" {
		t.Fatalf("an old client cannot be timed: %+v", r)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("an old client must fail fast, took %s", time.Since(start))
	}

	bob.ys.Close()
	alice.waitState(t, func(s State) bool { return len(s.Contacts) == 1 && !s.Contacts[0].Online })
	if r := ping(t, alice, "bob@example.com", ""); r.OK {
		t.Fatalf("offline contact: %+v", r)
	}
}

func TestLastSeenIsReportedForOfflineContacts(t *testing.T) {
	_, cl := setup(t, "alice@example.com", "bob@example.com")
	alice, bob := cl[0], cl[1]
	befriend(t, alice, bob)

	before := time.Now().Add(-2 * time.Second).Unix()
	bob.ys.Close()
	st := alice.waitState(t, func(s State) bool { return len(s.Contacts) == 1 && !s.Contacts[0].Online })
	if got := st.Contacts[0].LastSeen; got < before || got > time.Now().Add(2*time.Second).Unix() {
		t.Fatalf("lastSeen = %d, want about now", got)
	}
}

func TestStorePersistsLastSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := NewStore(path)
	s.Seen("bob@example.com", time.Unix(1700000000, 0))
	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.LastSeen("bob@example.com"); got != 1700000000 {
		t.Fatalf("lastSeen after reload = %d", got)
	}
	if s2.LastSeen("nobody@example.com") != 0 {
		t.Fatal("unknown contact has no last seen")
	}
}
