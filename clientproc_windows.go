//go:build windows

package main

import (
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() { clientProcessLookup = windowsClientProcess }

var (
	modIphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTbl  = modIphlpapi.NewProc("GetExtendedTcpTable")
	modUser32              = windows.NewLazySystemDLL("user32.dll")
	procEnumWindows        = modUser32.NewProc("EnumWindows")
	procGetWindowThreadPID = modUser32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible    = modUser32.NewProc("IsWindowVisible")
	procGetWindow          = modUser32.NewProc("GetWindow")
	procGetWindowTextLenW  = modUser32.NewProc("GetWindowTextLengthW")
	procGetWindowTextW     = modUser32.NewProc("GetWindowTextW")
)

const (
	tcpTableOwnerPIDAll = 5 // TCP_TABLE_OWNER_PID_ALL
	gwOwner             = 4 // GW_OWNER
)

func windowsClientProcess(ip net.IP, port int) (*ClientProcess, error) {
	pid, err := windowsSocketOwner(ip, port)
	if err != nil {
		return nil, err
	}
	if p, ok := procCache.get(pid); ok {
		return p, nil
	}
	p := readWindowsProcess(pid)
	procCache.put(pid, p)
	return p, nil
}

// windowsSocketOwner asks for the table of TCP connections with their owners.
// Windows lets any user read it for every program.
func windowsSocketOwner(ip net.IP, port int) (int, error) {
	if ip4 := ip.To4(); ip4 != nil {
		if pid, ok := scanWindowsTable(afINET, ip4, port); ok {
			return pid, nil
		}
	}
	if pid, ok := scanWindowsTable(afINET6, ip.To16(), port); ok {
		return pid, nil
	}
	return 0, errClientProcessNotFound
}

func scanWindowsTable(family uint32, ip net.IP, port int) (int, bool) {
	var size uint32
	for i := 0; i < 4; i++ {
		var buf []byte
		if size > 0 {
			buf = make([]byte, size)
		}
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		r, _, _ := procGetExtendedTCPTbl.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(family), tcpTableOwnerPIDAll, 0)
		if r == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if r != 0 || len(buf) < 4 {
			return 0, false
		}
		return findInWindowsTable(buf, family, ip, port)
	}
	return 0, false
}

func readWindowsProcess(pid int) *ClientProcess {
	p := &ClientProcess{PID: pid}
	refs := windowsProcessTable()
	if r, ok := refs[pid]; ok {
		p.Name = r.name
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err == nil {
		defer windows.CloseHandle(h)
		var buf [windows.MAX_LONG_PATH]uint16
		size := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) == nil {
			p.Exe = windows.UTF16ToString(buf[:size])
			if p.Name == "" {
				p.Name = filepath.Base(p.Exe)
			}
		}
		var creation, exit, kernel, usr windows.Filetime
		if windows.GetProcessTimes(h, &creation, &exit, &kernel, &usr) == nil {
			t := time.Unix(0, creation.Nanoseconds())
			p.Started = &t
		}
		var tok windows.Token
		if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) == nil {
			defer tok.Close()
			if u, err := tok.GetTokenUser(); err == nil {
				if account, domain, _, err := u.User.Sid.LookupAccount(""); err == nil {
					p.User = domain + `\` + account
				} else {
					p.User = u.User.Sid.String()
				}
			}
		}
	} else {
		p.Note = "details not readable: " + err.Error()
	}
	// the chain of parents; a program's parent may be gone and its number reused
	// by another one, so a parent that started after the program is dropped
	cur := pid
	for i := 0; i < 16; i++ {
		r, ok := refs[cur]
		if !ok || r.parent == 0 || r.parent == cur {
			break
		}
		par, ok := refs[r.parent]
		if !ok {
			break
		}
		ref := ProcessRef{PID: r.parent, Name: par.name}
		if ph, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(r.parent)); err == nil {
			var buf [windows.MAX_LONG_PATH]uint16
			size := uint32(len(buf))
			if windows.QueryFullProcessImageName(ph, 0, &buf[0], &size) == nil {
				ref.Exe = windows.UTF16ToString(buf[:size])
			}
			windows.CloseHandle(ph)
		}
		p.Parents = append(p.Parents, ref)
		cur = r.parent
	}
	p.Window = windowsWindowTitle(uint32(pid))
	return p
}

type winProc struct {
	name   string
	parent int
}

// windowsProcessTable lists every program with its parent.
func windowsProcessTable() map[int]winProc {
	out := map[int]winProc{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if windows.Process32First(snap, &e) != nil {
		return out
	}
	for {
		out[int(e.ProcessID)] = winProc{name: windows.UTF16ToString(e.ExeFile[:]), parent: int(e.ParentProcessID)}
		if windows.Process32Next(snap, &e) != nil {
			break
		}
	}
	return out
}

// windowsWindowTitle returns the title of the first visible top-level window
// without an owner that belongs to the program.
func windowsWindowTitle(pid uint32) string {
	var title string
	cb := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var wpid uint32
		procGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&wpid)))
		if wpid != pid {
			return 1
		}
		if v, _, _ := procIsWindowVisible.Call(hwnd); v == 0 {
			return 1
		}
		if o, _, _ := procGetWindow.Call(hwnd, gwOwner); o != 0 {
			return 1
		}
		n, _, _ := procGetWindowTextLenW.Call(hwnd)
		if n == 0 {
			return 1
		}
		buf := make([]uint16, n+1)
		procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), n+1)
		if t := strings.TrimSpace(windows.UTF16ToString(buf)); t != "" {
			title = t
			return 0 // stop
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
	return title
}
