package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/apeironlab/go-smart-proxy/relay"
)

func incomingReply(c *relayClient, line any) (relay.DialResp, bool) {
	a, b := net.Pipe()
	defer a.Close()
	go c.handleIncoming(b)
	if s, ok := line.(string); ok {
		a.Write([]byte(s))
	} else {
		relay.WriteLine(a, line)
	}
	a.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp relay.DialResp
	err := relay.ReadLine(relay.NewReader(a), &resp)
	return resp, err == nil
}

func TestHandleIncomingRefusals(t *testing.T) {
	old := configuration
	t.Cleanup(func() { configuration = old })
	c := &relayClient{email: "me@example.com", cfg: &RelayConfig{}, approvals: map[int64]*relayApproval{},
		state: relay.State{Contacts: []relay.Contact{{Email: "friend@example.com"}}}}

	if _, ok := incomingReply(c, "garbage\n"); ok {
		t.Error("an answer to garbage")
	}
	if _, ok := incomingReply(c, relay.DialReq{T: "teleport"}); ok {
		t.Error("an answer to an unknown request")
	}
	for name, req := range map[string]relay.DialReq{
		"no identity": {T: relay.TDial, From: "nonsense", Target: "example.org:80"},
		"a stranger":  {T: relay.TDial, From: "stranger@example.com", Target: "example.org:80"},
		"no port":     {T: relay.TDial, From: "friend@example.com", Target: "example.org"},
		"a bad port":  {T: relay.TDial, From: "friend@example.com", Target: "example.org:99999"},
		"no host":     {T: relay.TDial, From: "friend@example.com", Target: ":80"},
	} {
		if resp, ok := incomingReply(c, req); !ok || resp.OK || resp.Error == "" {
			t.Errorf("%s: %+v %v", name, resp, ok)
		}
	}
	if resp, ok := incomingReply(c, relay.DialReq{T: relay.TPing, From: "nonsense"}); !ok || resp.OK {
		t.Errorf("a probe without an identity: %+v", resp)
	}
	// once approved for the device, a destination on this machine is still refused by the guard
	c.rules = []relayRule{{ID: 1, From: "me@example.com", FromDevice: "k7m2p9qx", Host: "127.0.0.1", Port: 9}}
	if resp, ok := incomingReply(c, relay.DialReq{T: relay.TDial, From: "me@example.com", FromDevice: "k7m2p9qx", Target: "127.0.0.1:9"}); !ok || resp.OK || !strings.Contains(resp.Error, "not allowed") {
		t.Errorf("a loopback destination: %+v %v", resp, ok)
	}
}

func TestDialRequestFailures(t *testing.T) {
	c := &relayClient{}
	if _, err := c.dialRequest(relay.DialReq{T: relay.TDial}); err == nil {
		t.Error("dialed without a session")
	}
	if _, err := c.Dial("a@example.org", "", "example.org:80"); err == nil {
		t.Error("Dial without a session")
	}
	if _, err := c.Ping("a@example.org", ""); err == nil {
		t.Error("Ping without a session")
	}

	cc, sc := net.Pipe()
	srv, _ := yamux.Server(sc, nil)
	cli, _ := yamux.Client(cc, nil)
	t.Cleanup(func() { cli.Close(); srv.Close() })
	c.sess = cli
	go func() {
		for i := 0; ; i++ {
			st, err := srv.AcceptStream()
			if err != nil {
				return
			}
			go func(i int) {
				br := relay.NewReader(st)
				var req relay.DialReq
				relay.ReadLine(br, &req)
				switch req.Via {
				case "refuse@example.org":
					relay.WriteLine(st, relay.DialResp{}) // refused without a reason
				case "reason@example.org":
					relay.WriteLine(st, relay.DialResp{Error: "not your contact"})
				}
				st.Close() // and for anyone else: no answer at all
			}(i)
		}
	}()
	if _, err := c.Dial("refuse@example.org", "", "example.org:80"); err == nil || err.Error() != "refused" {
		t.Errorf("refusal without a reason: %v", err)
	}
	if _, err := c.Dial("reason@example.org", "", "example.org:80"); err == nil || err.Error() != "not your contact" {
		t.Errorf("refusal with a reason: %v", err)
	}
	if _, err := c.Dial("silent@example.org", "", "example.org:80"); err == nil {
		t.Error("a stream closed without an answer")
	}
	if _, err := c.Ping("refuse@example.org", ""); err == nil || err.Error() != "refused" {
		t.Errorf("a refused ping: %v", err)
	}
	if _, err := c.Ping("silent@example.org", ""); err == nil {
		t.Error("a ping without an answer")
	}
	// a session that is gone
	cli.Close()
	if _, err := c.dialRequest(relay.DialReq{T: relay.TDial}); err == nil {
		t.Error("dialed through a closed session")
	}
}
