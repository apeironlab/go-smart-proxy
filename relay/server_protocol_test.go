package relay

import (
	"net"
	"strings"
	"testing"
	"time"
)

// closedByServer reports whether the server closes the stream (without
// answering) within a moment.
func closedByServer(st net.Conn) bool {
	st.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	_, err := st.Read(buf)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return err != nil
}

func TestServerRefusesMalformedStreams(t *testing.T) {
	addr, _, pool, cl := setupWithDir(t, "alice@example.com")
	_ = addr
	_ = pool
	alice := cl[0]
	alice.state(t) // the control stream is up

	for name, line := range map[string]string{
		"not json":      "this is not json\n",
		"unknown type":  `{"t":"teleport"}` + "\n",
		"control twice": `{"t":"control"}` + "\n",
		"bad dial":      `{"t":"dial","via":5}` + "\n",
		"bad ping":      `{"t":"ping","via":5}` + "\n",
		"bad renew":     `{"t":"renew","csr":5}` + "\n",
		"bad control":   `{"t":"control","device":5}` + "\n",
	} {
		st, err := alice.ys.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		st.Write([]byte(line))
		if !closedByServer(st) {
			t.Errorf("%s: the stream stayed open", name)
		}
		st.Close()
	}
	// a stream that never says anything is dropped after the first-line timeout
	// (not waited for here), and an empty hello closes at once
	st, _ := alice.ys.OpenStream()
	st.Close()
}

func TestControlCommandsAndNotices(t *testing.T) {
	_, _, _, cl := setupWithDir(t, "alice@example.com")
	alice := cl[0]
	alice.state(t)

	WriteLine(alice.ctrl, ClientMsg{T: TContactRequest, Email: "nonsense"})
	st := alice.waitState(t, func(s State) bool { return strings.Contains(s.Notice, "invalid e-mail") })
	if st.Notice == "" {
		t.Error("no notice for an invalid address")
	}
	WriteLine(alice.ctrl, ClientMsg{T: "dance", Email: "bob@example.com"})
	alice.waitState(t, func(s State) bool { return s.Notice == "unknown command" })
	WriteLine(alice.ctrl, ClientMsg{T: TContactRequest, Email: "alice@example.com"})
	alice.waitState(t, func(s State) bool { return s.Notice != "" })
	// the device tells its contacts which network it is on
	WriteLine(alice.ctrl, ClientMsg{T: TContext, Context: &NetContext{Label: "Home", VPN: true}})
	alice.waitState(t, func(s State) bool {
		for _, d := range s.MyDevices {
			if d.Context != nil && d.Context.Label == "Home" && d.Context.VPN {
				return true
			}
		}
		return false
	})
}

func TestDialAndPingRefusals(t *testing.T) {
	_, _, _, cl := setupWithDir(t, "alice@example.com", "bob@example.com")
	alice, bob := cl[0], cl[1]
	alice.state(t)
	bob.state(t)

	ask := func(c *testClient, req DialReq) DialResp {
		t.Helper()
		st, err := c.ys.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		WriteLine(st, req)
		var resp DialResp
		st.SetReadDeadline(time.Now().Add(8 * time.Second))
		if err := ReadLine(NewReader(st), &resp); err != nil {
			t.Fatalf("%+v: %v", req, err)
		}
		return resp
	}
	for name, req := range map[string]DialReq{
		"bad target":       {T: TDial, Via: "bob@example.com", Target: "no port"},
		"bad via":          {T: TDial, Via: "nonsense", Target: "127.0.0.1:9"},
		"bad device":       {T: TDial, Via: "bob@example.com", ViaDevice: "bad device!", Target: "127.0.0.1:9"},
		"not a contact":    {T: TDial, Via: "bob@example.com", Target: "127.0.0.1:9"},
		"ping not contact": {T: TPing, Via: "bob@example.com"},
		"ping bad via":     {T: TPing, Via: "nonsense"},
	} {
		if resp := ask(alice, req); resp.OK || resp.Error == "" {
			t.Errorf("%s: %+v", name, resp)
		}
	}
	// a probe without a destination only tests the link
	if resp := ask(alice, DialReq{T: TPing}); !resp.OK {
		t.Errorf("link probe: %+v", resp)
	}
	// once contacts: a device that is not there, and the device in use
	WriteLine(alice.ctrl, ClientMsg{T: TContactRequest, Email: "bob@example.com"})
	bob.waitState(t, func(s State) bool { return len(s.Incoming) == 1 })
	WriteLine(bob.ctrl, ClientMsg{T: TContactRespond, Email: "alice@example.com", Accept: true})
	alice.waitState(t, func(s State) bool { return len(s.Contacts) == 1 })

	if resp := ask(alice, DialReq{T: TDial, Via: "bob@example.com", ViaDevice: "zzzz9999", Target: "127.0.0.1:9"}); resp.OK || !strings.Contains(resp.Error, "offline") {
		t.Errorf("an unknown device: %+v", resp)
	}
	if resp := ask(alice, DialReq{T: TPing, Via: "bob@example.com", ViaDevice: "zzzz9999"}); resp.OK {
		t.Errorf("ping of an unknown device: %+v", resp)
	}
	if resp := ask(alice, DialReq{T: TDial, Via: "alice@example.com", Target: "127.0.0.1:9"}); resp.OK || !strings.Contains(resp.Error, "relay exit") {
		t.Errorf("dial through the device in use: %+v", resp)
	}
	if resp := ask(alice, DialReq{T: TPing, Via: "alice@example.com"}); resp.OK || !strings.Contains(resp.Error, "device you are using") {
		t.Errorf("ping of the device in use: %+v", resp)
	}
}
