// Package winutil contains Windows-only helpers: admin detection, UAC
// self-elevation, and a single-instance mutex.
package winutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"foxyvpn/internal/settings"
)

const mutexName = "Local\\FoxyVPN-SingleInstance"
const activateEventName = "Local\\FoxyVPN-Activate"

var mutexHandle windows.Handle

// permissiveSA builds security attributes that let processes at any
// integrity level (e.g. a non-elevated instance signalling an elevated one)
// open our named objects.
func permissiveSA() *windows.SecurityAttributes {
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;WD)")
	if err != nil {
		return nil
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}
}

// AcquireSingleInstance returns false if another instance is running. It
// retries for a few seconds first: the elevated relaunch (UAC tunnel mode)
// may start while the original instance is still shutting down.
func AcquireSingleInstance() bool {
	name, err := syscall.UTF16PtrFromString(mutexName)
	if err != nil {
		return true
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		h, err := windows.CreateMutex(nil, true, name)
		if err == nil {
			mutexHandle = h
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// ReleaseSingleInstance releases the mutex on exit.
func ReleaseSingleInstance() {
	if mutexHandle != 0 {
		_ = windows.ReleaseMutex(mutexHandle)
		_ = windows.CloseHandle(mutexHandle)
	}
}

// NotifyRunningInstance signals the already-running instance to show its
// window. Returns true when a running instance was signalled.
func NotifyRunningInstance() bool {
	name, err := syscall.UTF16PtrFromString(activateEventName)
	if err != nil {
		return false
	}
	h, err := windows.CreateEventEx(permissiveSA(), name, 0, windows.EVENT_MODIFY_STATE)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	return windows.SetEvent(h) == nil
}

// WatchActivation calls onSignal whenever another instance requests the
// window to be shown. Blocks a helper goroutine for the process lifetime.
func WatchActivation(onSignal func()) {
	name, err := syscall.UTF16PtrFromString(activateEventName)
	if err != nil {
		return
	}
	h, err := windows.CreateEventEx(permissiveSA(), name, 0, windows.SYNCHRONIZE|windows.EVENT_MODIFY_STATE)
	if err != nil {
		return
	}
	go func() {
		for {
			ev, err := windows.WaitForSingleObject(h, windows.INFINITE)
			if err != nil || ev == windows.WAIT_FAILED {
				return
			}
			onSignal()
		}
	}()
}

// IsAdmin reports whether the current process runs elevated.
func IsAdmin() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// SelfElevate relaunches this executable with the UAC "runas" verb and
// returns true when the relaunch was initiated. The caller should exit.
func SelfElevate() (bool, error) {
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	exe = strings.TrimSpace(exe)
	// Escape for PowerShell single-quoted string.
	psExe := strings.ReplaceAll(exe, "'", "''")
	script := fmt.Sprintf(
		"Start-Process -FilePath '%s' -Verb RunAs",
		psExe,
	)
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return false, err
	}
	go cmd.Wait()
	return true, nil
}

// WintunDllPresent checks that wintun.dll sits next to the executable.
func WintunDllPresent() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	_, err = os.Stat(strings.TrimSuffix(exe, ".exe") + "" /* noop */)
	_ = err
	dir := dirOf(exe)
	_, err = os.Stat(dir + "\\wintun.dll")
	return err == nil
}

func dirOf(path string) string {
	i := strings.LastIndexAny(path, "\\/")
	if i < 0 {
		return "."
	}
	return path[:i]
}

// EnsureWintunDll makes wintun.dll available for tunnel mode: it prefers
// writing the embedded copy next to the exe; if that fails (read-only
// location) it writes to the data dir and adds it to the DLL search path.
func EnsureWintunDll(embedded []byte) error {
	if len(embedded) == 0 {
		return nil
	}
	exePath := filepath.Join(settings.ExeDir(), "wintun.dll")
	if _, err := os.Stat(exePath); err == nil {
		return nil
	}
	if err := os.WriteFile(exePath, embedded, 0o644); err == nil {
		return nil
	}
	dataDir := os.Getenv("APPDATA")
	dir := filepath.Join(dataDir, "FoxyVPN")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dllPath := filepath.Join(dir, "wintun.dll")
	if err := os.WriteFile(dllPath, embedded, 0o644); err != nil {
		return err
	}
	return setDllDirectory(dir)
}

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")
var procSetDllDirectory = kernel32.NewProc("SetDllDirectoryW")

func setDllDirectory(path string) error {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, _ := procSetDllDirectory.Call(uintptr(unsafe.Pointer(ptr)))
	if r == 0 {
		return fmt.Errorf("SetDllDirectory failed")
	}
	return nil
}

// ---- Windows system proxy (WinINET) ----

var (
	wininet              = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOption = wininet.NewProc("InternetSetOptionW")
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

// SystemProxyBackup captures the previous user proxy configuration so it can
// be restored when the VPN disconnects.
type SystemProxyBackup struct {
	Enable          uint32
	Server          string
	Override        string
	ServerExisted   bool
	OverrideExisted bool
	Valid           bool
}

const inetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// ReadSystemProxy returns the current user proxy configuration.
func ReadSystemProxy() SystemProxyBackup {
	backup := SystemProxyBackup{}
	key, err := registry.OpenKey(registry.CURRENT_USER, inetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return backup
	}
	defer key.Close()
	if enable, valType, err := key.GetIntegerValue("ProxyEnable"); err == nil && valType == registry.DWORD {
		backup.Enable = uint32(enable)
	}
	if server, valType, err := key.GetStringValue("ProxyServer"); err == nil && valType == registry.SZ {
		backup.Server = server
		backup.ServerExisted = true
	}
	if ov, valType, err := key.GetStringValue("ProxyOverride"); err == nil && valType == registry.SZ {
		backup.Override = ov
		backup.OverrideExisted = true
	}
	backup.Valid = true
	return backup
}

// ApplySystemProxy sets the user system proxy to server ("host:port" HTTP
// proxy, or "" to disable). The caller is responsible for backing up and
// restoring the previous values.
func ApplySystemProxy(server string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, inetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if server == "" {
		if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
			return err
		}
	} else {
		if err := key.SetStringValue("ProxyServer", server); err != nil {
			return err
		}
		if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
			return err
		}
		// Keep local addresses out of the tunnel proxy.
		_ = key.SetStringValue("ProxyOverride", "localhost;127.0.0.1;::1;<local>")
	}
	NotifyProxySettingsChanged()
	return nil
}

// RestoreSystemProxy puts back a previously captured configuration.
func RestoreSystemProxy(backup SystemProxyBackup) error {
	if !backup.Valid {
		return ApplySystemProxy("")
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, inetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if backup.ServerExisted {
		_ = key.SetStringValue("ProxyServer", backup.Server)
	} else {
		_ = key.DeleteValue("ProxyServer")
	}
	if backup.OverrideExisted {
		_ = key.SetStringValue("ProxyOverride", backup.Override)
	}
	_ = key.SetDWordValue("ProxyEnable", backup.Enable)
	NotifyProxySettingsChanged()
	return nil
}

// NotifyProxySettingsChanged makes running applications re-read the proxy.
func NotifyProxySettingsChanged() {
	procInternetSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOption.Call(0, internetOptionRefresh, 0, 0)
}

var _ = unsafe.Sizeof(0)
