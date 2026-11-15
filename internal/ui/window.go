package ui

import (
	"strings"
	"syscall"
	"unsafe"
)

var (
	modUser32               = syscall.NewLazyDLL("user32.dll")
	procEnumWindows         = modUser32.NewProc("EnumWindows")
	procIsWindowVisible     = modUser32.NewProc("IsWindowVisible")
	procGetWindowTextW      = modUser32.NewProc("GetWindowTextW")
	procGetClassNameW       = modUser32.NewProc("GetClassNameW")
	procIsIconic            = modUser32.NewProc("IsIconic")
	procShowWindow          = modUser32.NewProc("ShowWindow")
	procSetForegroundWindow = modUser32.NewProc("SetForegroundWindow")
)

const (
	swShow    = 5
	swRestore = 9
)

// focusExistingCommandCenterWindow finds an already-open ShieldSheriff Command Center
// browser/app window and brings it to the foreground.
func focusExistingCommandCenterWindow() bool {
	var found uintptr

	cb := syscall.NewCallback(func(hwnd uintptr, lparam uintptr) uintptr {
		vis, _, _ := procIsWindowVisible.Call(hwnd)
		if vis == 0 {
			return 1 // continue
		}

		var titleBuf [256]uint16
		n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&titleBuf[0])), uintptr(len(titleBuf)))
		if n == 0 {
			return 1
		}
		title := syscall.UTF16ToString(titleBuf[:n])
		if !strings.Contains(title, "ShieldSheriff") || !strings.Contains(title, "Command Center") {
			return 1
		}

		var classBuf [128]uint16
		cn, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&classBuf[0])), uintptr(len(classBuf)))
		className := ""
		if cn > 0 {
			className = syscall.UTF16ToString(classBuf[:cn])
		}

		// Match Chromium/Edge app or browser windows hosting the Command Center.
		if className == "Chrome_WidgetWin_1" || title == "ShieldSheriff — Command Center" {
			found = hwnd
			return 0 // stop enumeration
		}
		return 1
	})

	_, _, _ = procEnumWindows.Call(cb, 0)
	if found == 0 {
		return false
	}

	iconic, _, _ := procIsIconic.Call(found)
	if iconic != 0 {
		_, _, _ = procShowWindow.Call(found, swRestore)
	} else {
		_, _, _ = procShowWindow.Call(found, swShow)
	}
	_, _, _ = procSetForegroundWindow.Call(found)
	return true
}
