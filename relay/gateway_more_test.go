package relay

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewGatewayRefusesBadConfigurations(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca")
	InitCA(ca)
	IssueGateway(ca, dir, "gw1")
	ok := GatewayConfig{Address: "127.0.0.1:1", CertFile: filepath.Join(dir, "gateway.pem"), KeyFile: filepath.Join(dir, "gateway-key.pem"), CAFile: filepath.Join(dir, "ca.pem")}
	if _, err := NewGateway(ok); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(c *GatewayConfig){
		"no address": func(c *GatewayConfig) { c.Address = "" },
		"no cert":    func(c *GatewayConfig) { c.CertFile = filepath.Join(dir, "none.pem") },
		"no key":     func(c *GatewayConfig) { c.KeyFile = filepath.Join(dir, "none-key.pem") },
		"no ca":      func(c *GatewayConfig) { c.CAFile = filepath.Join(dir, "none-ca.pem") },
		"ca not a ca": func(c *GatewayConfig) {
			os.WriteFile(filepath.Join(dir, "x.pem"), []byte("x"), 0o600)
			c.CAFile = filepath.Join(dir, "x.pem")
		},
	} {
		c := ok
		mod(&c)
		if _, err := NewGateway(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGatewayStreams(t *testing.T) {
	env, _, gateway := newAppRelay(t)
	g := gateway("gw1")
	_ = g
	_ = env
	// wait until the gateway is connected to the relay
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if env.srv.gatewayOnline("gw1") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// straight to the gateway's side: a stream that is not a dial, and an unknown app
	a, b := net.Pipe()
	go g.handleStream(b)
	a.Write([]byte("{\"t\":\"nonsense\"}\n"))
	if !closedByServer(a) {
		t.Error("a bad request kept the stream open")
	}
	a.Close()
	a, b = net.Pipe()
	go g.handleStream(b)
	WriteLine(a, DialReq{T: TDial, App: "nope"})
	var resp DialResp
	a.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := ReadLine(NewReader(a), &resp); err != nil || resp.OK || resp.Error == "" {
		t.Errorf("unknown application: %+v %v", resp, err)
	}
	a.Close()
}

func TestDialWithoutCatalog(t *testing.T) {
	_, _, _, cl := setupWithDir(t, "alice@example.com")
	alice := cl[0]
	alice.state(t)
	st, _ := alice.ys.OpenStream()
	defer st.Close()
	WriteLine(st, DialReq{T: TDial, App: "wiki"})
	var resp DialResp
	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := ReadLine(NewReader(st), &resp); err != nil || resp.OK {
		t.Errorf("an application without a catalog: %+v %v", resp, err)
	}
}
