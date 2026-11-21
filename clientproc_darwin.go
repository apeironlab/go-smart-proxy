//go:build darwin

package main

import (
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func init() { clientProcessLookup = darwinClientProcess }

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return strings.TrimRight(string(out), "\r\n"), err
}

// darwinClientProcess asks lsof, which is part of the system, for the owner of
// the client end of the connection, then ps for the details. A user who is not
// root sees the programs of their own user only, which is what is wanted.
func darwinClientProcess(ip net.IP, port int) (*ClientProcess, error) {
	local := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	out, err := run("lsof", "-nP", "-a", "-iTCP:"+strconv.Itoa(port), "-F", "pcn")
	if err != nil && out == "" {
		return nil, errClientProcessNotFound
	}
	pid, name, ok := parseLsofOwner(out, local)
	if !ok {
		return nil, errClientProcessNotFound
	}
	if p, ok := procCache.get(pid); ok {
		return p, nil
	}
	p := &ClientProcess{PID: pid, Name: name}
	ps := func(field string, pid int) string {
		s, _ := run("ps", "-o", field+"=", "-p", strconv.Itoa(pid))
		return strings.TrimSpace(s)
	}
	if exe := ps("comm", pid); exe != "" {
		p.Exe = exe
		p.Name = filepath.Base(exe)
	}
	p.Cmdline = ps("command", pid)
	p.User = ps("user", pid)
	if t, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", ps("lstart", pid), time.Local); err == nil {
		p.Started = &t
	}
	cur := pid
	for i := 0; i < 16; i++ {
		ppid, err := strconv.Atoi(ps("ppid", cur))
		if err != nil || ppid <= 0 || ppid == cur {
			break
		}
		ref := ProcessRef{PID: ppid}
		if exe := ps("comm", ppid); exe != "" {
			ref.Exe = exe
			ref.Name = filepath.Base(exe)
		}
		p.Parents = append(p.Parents, ref)
		cur = ppid
	}
	procCache.put(pid, p)
	return p, nil
}
