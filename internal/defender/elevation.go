package defender

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modShell32  = syscall.NewLazyDLL("shell32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetTokenInformation = modAdvapi32.NewProc("GetTokenInformation")
	procShellExecuteW       = modShell32.NewProc("ShellExecuteW")
)

const (
	tokenQuery          = 0x0008
	tokenElevationClass = 20
	swHide              = 0
	swShowNormal        = 1
)

type tokenElevation struct {
	TokenIsElevated uint32
}

// IsProcessElevated returns true if the current process has an elevated Administrator or SYSTEM token.
func IsProcessElevated() bool {
	var token syscall.Token
	currProc, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	err = syscall.OpenProcessToken(currProc, tokenQuery, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	var elev tokenElevation
	var retLen uint32
	r1, _, _ := procGetTokenInformation.Call(
		uintptr(token),
		uintptr(tokenElevationClass),
		uintptr(unsafe.Pointer(&elev)),
		unsafe.Sizeof(elev),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r1 == 0 {
		return false
	}
	return elev.TokenIsElevated != 0
}

// RelaunchElevated launches a new instance of the current executable with Administrator privileges via UAC ("runas").
func RelaunchElevated(extraArgs []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)

	var argStr string
	if len(extraArgs) > 0 {
		quoted := make([]string, 0, len(extraArgs))
		for _, a := range extraArgs {
			if strings.ContainsAny(a, " \t\"") {
				quoted = append(quoted, `"`+strings.ReplaceAll(a, `"`, `\"`)+`"`)
			} else {
				quoted = append(quoted, a)
			}
		}
		argStr = strings.Join(quoted, " ")
	}
	argPtr, _ := syscall.UTF16PtrFromString(argStr)
	cwd, _ := os.Getwd()
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)

	showCmd := uintptr(swShowNormal)
	if len(extraArgs) > 0 {
		switch strings.ToLower(extraArgs[0]) {
		case "ui", "tray", "dashboard", "--minimized":
			showCmd = uintptr(swHide)
		}
	}

	r1, _, lastErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(argPtr)),
		uintptr(unsafe.Pointer(cwdPtr)),
		showCmd,
	)
	// ShellExecuteW returns a value > 32 on success.
	if r1 <= 32 {
		if lastErr != nil && lastErr != syscall.Errno(0) {
			return lastErr
		}
		return syscall.EACCES
	}
	return nil
}

// OpenWindowsSecuritySettings opens the Windows Security "Virus & threat protection settings" page
// where the user can perform the one-time Tamper Protection toggle.
func OpenWindowsSecuritySettings() error {
	verbPtr, _ := syscall.UTF16PtrFromString("open")
	uriPtr, _ := syscall.UTF16PtrFromString("windowsdefender://threatsettings")
	r1, _, lastErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(uriPtr)),
		0,
		0,
		swShowNormal,
	)
	if r1 <= 32 {
		return lastErr
	}
	return nil
}
