package relay

import (
	"crypto/tls"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeContext(t *testing.T) {
	if SanitizeContext(nil) != nil {
		t.Fatal("a device that shares nothing stays nil")
	}
	got := SanitizeContext(&NetContext{Label: "  office\x00-vpn\r\n  ", VPN: true})
	if got.Label != "office-vpn" || !got.VPN {
		t.Fatalf("control characters must go: %+v", got)
	}
	long := SanitizeContext(&NetContext{Label: strings.Repeat("x", 500)})
	if len(long.Label) > MaxLabelLen {
		t.Fatalf("label not bounded: %d", len(long.Label))
	}
	if g := SanitizeContext(&NetContext{}); g == nil || g.Label != "" || g.VPN {
		t.Fatalf("an explicit empty context is kept: %+v", g)
	}
}

func contextOf(s State, contact, device string) (NetContext, bool) {
	for _, c := range s.Contacts {
		if c.Email == contact {
			v, ok := c.Context[device]
			return v, ok
		}
	}
	return NetContext{}, false
}

func TestContactsSeeSharedContext(t *testing.T) {
	addr, dir, pool, cl := setupWithDir(t, "alice@example.com", "bob@example.com", "carol@example.com")
	alice, bob, carol := cl[0], cl[1], cl[2]
	befriend(t, alice, bob)

	// bob joins a second device that shares its context right in the hello
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "bob@example.com", "client.pem"), filepath.Join(dir, "bob@example.com", "client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	bob2 := connectTestClientWithHello(t, addr, pool, cert, "bob@example.com", DialReq{T: TControl, Device: "laptop", Context: &NetContext{Label: "office-vpn", VPN: true}})

	st := alice.waitState(t, func(s State) bool { _, ok := contextOf(s, "bob@example.com", "laptop"); return ok })
	c, _ := contextOf(st, "bob@example.com", "laptop")
	if c.Label != "office-vpn" || !c.VPN {
		t.Fatalf("alice must see bob's context: %+v", c)
	}

	// the context changes while connected
	WriteLine(bob2.ctrl, ClientMsg{T: TContext, Context: &NetContext{Label: "home", VPN: false}})
	st = alice.waitState(t, func(s State) bool { v, ok := contextOf(s, "bob@example.com", "laptop"); return ok && v.Label == "home" })
	if c, _ := contextOf(st, "bob@example.com", "laptop"); c.VPN {
		t.Fatalf("update not applied: %+v", c)
	}

	// sharing switched off: the device disappears from the map but stays online
	WriteLine(bob2.ctrl, ClientMsg{T: TContext})
	st = alice.waitState(t, func(s State) bool { _, ok := contextOf(s, "bob@example.com", "laptop"); return !ok })
	if len(st.Contacts) != 1 || !st.Contacts[0].Online {
		t.Fatalf("bob must stay online: %+v", st.Contacts)
	}

	// a stranger never receives it
	WriteLine(bob2.ctrl, ClientMsg{T: TContext, Context: &NetContext{Label: "secret"}})
	alice.waitState(t, func(s State) bool {
		v, ok := contextOf(s, "bob@example.com", "laptop")
		return ok && v.Label == "secret"
	})
	// carol is nobody's contact: the state pushed to her carries no contact at
	// all, so nothing about bob's network.
	cs := carol.state(t)
	if len(cs.Contacts) != 0 {
		t.Fatalf("carol is not bob's contact but sees %+v", cs.Contacts)
	}
}

func TestOwnDevicesSeeTheirContext(t *testing.T) {
	addr, dir, pool, cl := setupWithDir(t, "alice@example.com")
	alice := cl[0]
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "alice@example.com", "client.pem"), filepath.Join(dir, "alice@example.com", "client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	connectTestClientWithHello(t, addr, pool, cert, "alice@example.com", DialReq{T: TControl, Device: "phone", Context: &NetContext{Label: "mobile", VPN: true}})
	st := alice.waitState(t, func(s State) bool {
		for _, d := range s.MyDevices {
			if d.ID == "phone" && d.Online && d.Context != nil {
				return true
			}
		}
		return false
	})
	for _, d := range st.MyDevices {
		if d.ID == "phone" && (d.Context.Label != "mobile" || !d.Context.VPN) {
			t.Fatalf("own device context: %+v", d.Context)
		}
	}
}

func TestOversizedLabelIsBoundedOnTheServer(t *testing.T) {
	_, cl := setup(t, "alice@example.com", "bob@example.com")
	alice, bob := cl[0], cl[1]
	befriend(t, alice, bob)
	WriteLine(bob.ctrl, ClientMsg{T: TContext, Context: &NetContext{Label: strings.Repeat("a", 2000)}})
	st := alice.waitState(t, func(s State) bool {
		for _, c := range s.Contacts {
			for _, v := range c.Context {
				_ = v
				return true
			}
		}
		return false
	})
	for _, c := range st.Contacts {
		for _, v := range c.Context {
			if len(v.Label) > MaxLabelLen {
				t.Fatalf("label of %d bytes got through", len(v.Label))
			}
		}
	}
}
