//go:build windows

package main

import (
	"log"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

const inetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// registryProxy is the current user's Internet Options.
type registryProxy struct{}

func (registryProxy) read() (winProxySettings, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return winProxySettings{}, err
	}
	defer k.Close()
	var s winProxySettings
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		s.Enable = v != 0
	}
	s.Server, _, _ = k.GetStringValue("ProxyServer")
	s.Override, _, _ = k.GetStringValue("ProxyOverride")
	s.AutoConfigURL, _, _ = k.GetStringValue("AutoConfigURL")
	if v, _, err := k.GetIntegerValue("AutoDetect"); err == nil {
		s.AutoDetect = v != 0
	}
	return s, nil
}

func (registryProxy) write(s winProxySettings) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	b := func(v bool) uint32 {
		if v {
			return 1
		}
		return 0
	}
	if err := k.SetDWordValue("ProxyEnable", b(s.Enable)); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", s.Server); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", s.Override); err != nil {
		return err
	}
	if s.AutoConfigURL == "" {
		if err := k.DeleteValue("AutoConfigURL"); err != nil && err != registry.ErrNotExist {
			return err
		}
	} else if err := k.SetStringValue("AutoConfigURL", s.AutoConfigURL); err != nil {
		return err
	}
	if err := k.SetDWordValue("AutoDetect", b(s.AutoDetect)); err != nil {
		return err
	}
	notifyWinInet()
	return nil
}

// notifyWinInet tells running programs that the settings changed.
func notifyWinInet() {
	dll := syscall.NewLazyDLL("wininet.dll")
	set := dll.NewProc("InternetSetOptionW")
	const settingsChanged, refresh = 39, 37
	set.Call(0, settingsChanged, 0, 0)
	set.Call(0, refresh, 0, 0)
}

var (
	winProxyMu   sync.Mutex
	winLastApply time.Time
)

// applySystemProxy points the Windows system proxy at this proxy while the
// system proxy option is on. It is cheap when nothing changed (it is called
// every few seconds).
func applySystemProxy() {
	configMu.Lock()
	enabled := configuration.SystemProxy
	address := configuration.Address
	configMu.Unlock()
	if !enabled {
		return
	}
	winProxyMu.Lock()
	defer winProxyMu.Unlock()
	changed, err := applyWinProxy(registryProxy{}, address, winProxyBackup)
	if err != nil {
		if time.Since(winLastApply) > time.Minute {
			log.Printf("System proxy: %v", err)
			winLastApply = time.Now()
		}
		return
	}
	if changed {
		log.Printf("System proxy set to %s", winWanted(address).Server)
	}
}

// restoreSystemProxy puts back the settings the system had before.
func restoreSystemProxy() {
	configMu.Lock()
	address := configuration.Address
	configMu.Unlock()
	winProxyMu.Lock()
	defer winProxyMu.Unlock()
	if err := restoreWinProxy(registryProxy{}, address, winProxyBackup); err != nil {
		log.Printf("System proxy: cannot restore the previous settings: %v", err)
		return
	}
	log.Printf("System proxy settings restored")
}

func systemProxyState() systemProxyStateJSON {
	s, err := registryProxy{}.read()
	if err != nil {
		return systemProxyStateJSON{Raw: err.Error(), Exceptions: []string{}}
	}
	return winStateJSON(s)
}

// hideWindow keeps the console of a helper program from flashing.
func hideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
