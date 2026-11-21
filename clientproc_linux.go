//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func init() { clientProcessLookup = linuxClientProcess }

// linuxClientProcess finds the program that owns the client end of a
// connection. A user who is not root can read the files of the programs of
// their own user only: the connections of others stay unknown, which is what
// is wanted here.
func linuxClientProcess(ip net.IP, port int) (*ClientProcess, error) {
	inode, err := socketInode(ip, port)
	if err != nil {
		return nil, err
	}
	pid, err := pidOfSocket(inode)
	if err != nil {
		return nil, err
	}
	if p, ok := procCache.get(pid); ok {
		return p, nil
	}
	p := readLinuxProcess(pid)
	procCache.put(pid, p)
	return p, nil
}

// socketInode looks for the local address in the kernel's tables of TCP sockets.
func socketInode(ip net.IP, port int) (string, error) {
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if inode := scanTCPTable(f, ip, port); inode != "" {
			return inode, nil
		}
	}
	return "", errClientProcessNotFound
}

func scanTCPTable(path string, ip net.IP, port int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	want := fmt.Sprintf("%04X", port)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		addr, p, ok := strings.Cut(fields[1], ":")
		if !ok || p != want {
			continue
		}
		if tableAddrMatches(addr, ip) {
			return fields[9]
		}
	}
	return ""
}

// tableAddrMatches compares an address from /proc/net/tcp (each 32-bit word
// written backwards) with ip, whether the socket is IPv4 or IPv6, and an IPv4
// client on an IPv6 socket.
func tableAddrMatches(hexAddr string, ip net.IP) bool {
	raw, err := hex.DecodeString(hexAddr)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return false
	}
	for i := 0; i+3 < len(raw); i += 4 { // words are in host order, little endian here
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	if len(raw) == 4 {
		return ip.To4() != nil && ip.To4().Equal(net.IP(raw))
	}
	got := net.IP(raw)
	if got.Equal(ip) {
		return true
	}
	return ip.To4() != nil && got.To4() != nil && got.To4().Equal(ip.To4())
}

// pidOfSocket finds, among the programs the user may look at, the one that has
// the socket open.
func pidOfSocket(inode string) (int, error) {
	target := "socket:[" + inode + "]"
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		fds, err := os.ReadDir(d + "/fd")
		if err != nil {
			continue // another user's program
		}
		for _, fd := range fds {
			if l, err := os.Readlink(d + "/fd/" + fd.Name()); err == nil && l == target {
				pid, _ := strconv.Atoi(filepath.Base(d))
				return pid, nil
			}
		}
	}
	return 0, errClientProcessNotFound
}

func readLinuxProcess(pid int) *ClientProcess {
	p := &ClientProcess{PID: pid}
	dir := "/proc/" + strconv.Itoa(pid)
	if b, err := os.ReadFile(dir + "/comm"); err == nil {
		p.Name = strings.TrimSpace(string(b))
	}
	if exe, err := os.Readlink(dir + "/exe"); err == nil {
		p.Exe = exe
		if p.Name == "" {
			p.Name = filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		}
	}
	if b, err := os.ReadFile(dir + "/cmdline"); err == nil {
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " "))
	}
	if b, err := os.ReadFile(dir + "/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
				if f := strings.Fields(rest); len(f) > 0 {
					p.User = f[0]
					if u, err := user.LookupId(f[0]); err == nil {
						p.User = u.Username
					}
				}
				break
			}
		}
	}
	ppid, start := linuxStat(pid)
	if !start.IsZero() {
		p.Started = &start
	}
	// the chain of parents, up to the first program the system does not show
	for i := 0; i < 16 && ppid > 0; i++ {
		ref := ProcessRef{PID: ppid}
		d := "/proc/" + strconv.Itoa(ppid)
		if b, err := os.ReadFile(d + "/comm"); err == nil {
			ref.Name = strings.TrimSpace(string(b))
		}
		if exe, err := os.Readlink(d + "/exe"); err == nil {
			ref.Exe = exe
		}
		p.Parents = append(p.Parents, ref)
		next, _ := linuxStat(ppid)
		if next == ppid {
			break
		}
		ppid = next
	}
	p.Window = linuxWindowTitle(pid)
	return p
}

// linuxStat returns the parent of a program and when it started, from
// /proc/<pid>/stat. The name in that file is in parentheses and may contain
// spaces and parentheses: the fields that matter come after the last ")".
func linuxStat(pid int) (int, time.Time) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, time.Time{}
	}
	ppid, ticks, ok := parseProcStat(string(b))
	if !ok {
		return 0, time.Time{}
	}
	return ppid, bootTime().Add(time.Duration(ticks) * 10 * time.Millisecond) // 100 ticks per second
}

// parseProcStat reads the parent and the start time (in clock ticks since
// boot) from the text of /proc/<pid>/stat.
func parseProcStat(s string) (ppid int, ticks int64, ok bool) {
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return 0, 0, false
	}
	f := strings.Fields(s[i+1:])
	// f[0] state, f[1] ppid, ..., f[19] starttime
	if len(f) < 20 {
		return 0, 0, false
	}
	ppid, err1 := strconv.Atoi(f[1])
	ticks, err2 := strconv.ParseInt(f[19], 10, 64)
	return ppid, ticks, err1 == nil && err2 == nil
}

func bootTime() time.Time {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			if sec, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); err == nil {
				return time.Unix(sec, 0)
			}
		}
	}
	return time.Time{}
}

// linuxWindowTitle asks the X server, when there is one and xprop is
// installed, for the title of a window of the program. Wayland does not let
// programs see the windows of others: there the answer is empty.
func linuxWindowTitle(pid int) string {
	if os.Getenv("DISPLAY") == "" {
		return ""
	}
	xprop, err := exec.LookPath("xprop")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, xprop, "-root", "_NET_CLIENT_LIST").Output()
	if err != nil {
		return ""
	}
	_, list, ok := strings.Cut(string(out), "#")
	if !ok {
		return ""
	}
	for _, id := range strings.Split(list, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		info, err := exec.CommandContext(ctx, xprop, "-id", id, "_NET_WM_PID", "_NET_WM_NAME").Output()
		if err != nil {
			continue
		}
		if title, ok := windowOfPID(string(info), pid); ok {
			return title
		}
	}
	return ""
}

// windowOfPID reads the answer of xprop for a window: it returns the title
// when the window belongs to pid.
func windowOfPID(xpropOut string, pid int) (string, bool) {
	owner, title := -1, ""
	for _, line := range strings.Split(xpropOut, "\n") {
		switch {
		case strings.HasPrefix(line, "_NET_WM_PID"):
			if _, v, ok := strings.Cut(line, "="); ok {
				owner, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		case strings.HasPrefix(line, "_NET_WM_NAME"):
			if _, v, ok := strings.Cut(line, "="); ok {
				title = strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	if owner == pid && title != "" {
		return title, true
	}
	return "", false
}
