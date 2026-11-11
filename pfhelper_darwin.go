//go:build darwin

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The privileged helper of the transparent routing. The program starts it
// as root, after the user authenticated (see pfauth_darwin.go), by running a
// copy of its own binary with --pf-helper. The helper does only what needs
// root:
//
//   - load and remove the packet filter anchor, from a list of interfaces:
//     it builds the rules itself, so the unprivileged side cannot make it
//     load arbitrary rules;
//   - tell which is the original destination of a redirected connection.
//
// It talks to the program over a Unix socket that only the user who started
// it can open, and it exits (removing the rules) when the program is gone.

var ifaceNameRE = regexp.MustCompile(`^[a-z]{1,16}[0-9]{1,4}$`)

type helperRequest struct {
	Op     string   `json:"op"`
	Ifaces []string `json:"ifaces,omitempty"`
	Src    string   `json:"src,omitempty"`
}

type helperResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Dst   string `json:"dst,omitempty"`
}

// pfctlBin is the packet filter control program (replaced in tests).
var pfctlBin = "/sbin/pfctl"

// parsePfStates reads the output of `pfctl -ss` and returns, for the states
// redirected to the transparent listener, the original destination by client
// address:  "ALL tcp 127.0.0.1:3129 <- 8.8.8.8:443 <- 10.13.169.227:64682  ..."
func parsePfStates(out, listen string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// proto-family proto redirected <- original <- client state
		if len(f) < 7 || f[3] != "<-" || f[5] != "<-" || f[2] != listen {
			continue
		}
		m[f[6]] = f[4]
	}
	return m
}

type pfHelper struct {
	mu     sync.Mutex // serialises the pfctl calls
	token  string
	loaded bool
}

func (h *pfHelper) pfctl(stdin string, args ...string) (string, error) {
	cmd := exec.Command(pfctlBin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (h *pfHelper) load(ifaces []string) error {
	if len(ifaces) == 0 {
		return fmt.Errorf("no interface")
	}
	for _, i := range ifaces {
		if !ifaceNameRE.MatchString(i) {
			return fmt.Errorf("invalid interface name %q", i)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.token == "" {
		out, err := h.pfctl("", "-E")
		if err != nil {
			return err
		}
		for _, l := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "Token" {
				h.token = strings.TrimSpace(v)
			}
		}
	}
	if _, err := h.pfctl(pfRules(ifaces, transparentAddr), "-a", pfAnchor, "-f", "-"); err != nil {
		return err
	}
	h.loaded = true
	return nil
}

func (h *pfHelper) flush() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.loaded {
		return nil
	}
	if _, err := h.pfctl("", "-a", pfAnchor, "-F", "all"); err != nil {
		return err
	}
	h.loaded = false
	return nil
}

// release flushes the anchor and gives back the reference taken on pf.
func (h *pfHelper) release() {
	h.flush()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.token != "" {
		h.pfctl("", "-X", h.token)
		h.token = ""
	}
}

func (h *pfHelper) lookup(src string) (string, error) {
	if _, _, err := net.SplitHostPort(src); err != nil {
		return "", err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// The state exists as soon as the SYN is redirected: it is there when the
	// program accepts the connection; retry once for the rare race.
	for try := 0; try < 2; try++ {
		out, err := h.pfctl("", "-ss")
		if err != nil {
			return "", err
		}
		if dst, ok := parsePfStates(out, transparentAddr)[src]; ok {
			return dst, nil
		}
		time.Sleep(30 * time.Millisecond)
	}
	return "", fmt.Errorf("no redirected connection from %s", src)
}

func (h *pfHelper) handle(c net.Conn, uid uint32, quit chan<- struct{}) {
	defer c.Close()
	if cred, err := peerCred(c); err != nil || cred != uid {
		return
	}
	r := bufio.NewReader(c)
	enc := json.NewEncoder(c)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var req helperRequest
		resp := helperResponse{OK: true}
		if err := json.Unmarshal(line, &req); err != nil {
			resp = helperResponse{Error: "bad request"}
		} else {
			switch req.Op {
			case "ping":
			case "load":
				if err := h.load(req.Ifaces); err != nil {
					resp = helperResponse{Error: err.Error()}
				}
			case "flush":
				if err := h.flush(); err != nil {
					resp = helperResponse{Error: err.Error()}
				}
			case "lookup":
				dst, err := h.lookup(req.Src)
				if err != nil {
					resp = helperResponse{Error: err.Error()}
				} else {
					resp.Dst = dst
				}
			case "quit":
				enc.Encode(resp)
				select {
				case quit <- struct{}{}:
				default:
				}
				return
			default:
				resp = helperResponse{Error: "unknown operation"}
			}
		}
		if enc.Encode(resp) != nil {
			return
		}
	}
}

// peerCred returns the uid of the process on the other side of a Unix socket.
func peerCred(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var serr error
	if err := raw.Control(func(fd uintptr) {
		x, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			serr = e
			return
		}
		uid = x.Uid
	}); err != nil {
		return 0, err
	}
	return uid, serr
}

// runPFHelper is the entry point of `proxy --pf-helper <socket> <uid> <ppid>`.
func runPFHelper(args []string) int {
	if len(args) != 3 || os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "usage (as root): --pf-helper <socket> <uid> <parent pid>")
		return 2
	}
	sock := args[0]
	uid64, err1 := strconv.ParseUint(args[1], 10, 32)
	ppid, err2 := strconv.Atoi(args[2])
	if err1 != nil || err2 != nil || uid64 == 0 || !strings.HasPrefix(sock, "/var/run/proxyroute-") {
		fmt.Fprintln(os.Stderr, "invalid arguments")
		return 2
	}
	uid := uint32(uid64)

	os.Remove(sock)
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", sock)
	syscall.Umask(old)
	if err != nil {
		log.Printf("pf helper: %v", err)
		return 1
	}
	defer os.Remove(sock)
	if err := os.Chown(sock, int(uid), 0); err != nil {
		log.Printf("pf helper: %v", err)
		return 1
	}

	h := &pfHelper{}
	quit := make(chan struct{}, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h.handle(c, uid, quit)
		}
	}()

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-quit:
			h.release()
			return 0
		case <-tick.C:
			if syscall.Kill(ppid, 0) == syscall.ESRCH {
				h.release()
				return 0
			}
		}
	}
}
