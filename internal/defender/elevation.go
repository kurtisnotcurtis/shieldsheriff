//go:build windows

package defender

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	swHide       = 0
	swShowNormal = 1
)

// IsProcessElevated returns true if the current process has an elevated Administrator or SYSTEM token.
func IsProcessElevated() bool {
	return DefaultBackend().IsElevated()
}

// RelaunchElevated launches a new instance of the current executable with Administrator privileges via UAC ("runas").
func RelaunchElevated(extraArgs []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verbPtr, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	exePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}

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
	argPtr, err := windows.UTF16PtrFromString(argStr)
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	cwdPtr, err := windows.UTF16PtrFromString(cwd)
	if err != nil {
		return err
	}

	showCmd := int32(swShowNormal)
	if len(extraArgs) > 0 {
		switch strings.ToLower(extraArgs[0]) {
		case "ui", "tray", "dashboard", "--minimized":
			showCmd = int32(swHide)
		}
	}

	return windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
}

// OpenWindowsSecuritySettings opens the Windows Security "Virus & threat protection settings" page
// where the user can perform the one-time Tamper Protection toggle.
func OpenWindowsSecuritySettings() error {
	verbPtr, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	uriPtr, err := windows.UTF16PtrFromString("windowsdefender://threatsettings")
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verbPtr, uriPtr, nil, nil, swShowNormal)
}
