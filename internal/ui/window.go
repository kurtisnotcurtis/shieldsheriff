package ui

import (
	"strings"
	"syscall"
	"unsafe"

	"shieldsheriff/internal/tray"
)

var (
	modUser32               = syscall.NewLazyDLL("user32.dll")
	modDwmapi               = syscall.NewLazyDLL("dwmapi.dll")
	procEnumWindows         = modUser32.NewProc("EnumWindows")
	procIsWindowVisible     = modUser32.NewProc("IsWindowVisible")
	procGetWindowTextW      = modUser32.NewProc("GetWindowTextW")
	procGetClassNameW       = modUser32.NewProc("GetClassNameW")
	procIsIconic            = modUser32.NewProc("IsIconic")
	procShowWindow          = modUser32.NewProc("ShowWindow")
	procSetForegroundWindow = modUser32.NewProc("SetForegroundWindow")
	procPostMessageW        = modUser32.NewProc("PostMessageW")
	procSendMessageW        = modUser32.NewProc("SendMessageW")
	procDwmSetWindowAttr    = modDwmapi.NewProc("DwmSetWindowAttribute")
)

const (
	swShow    = 5
	swRestore = 9
	wmClose   = 0x0010
	wmSetIcon = 0x0080
	iconSmall = 0
	iconBig   = 1

	dwmwaUseImmersiveDarkMode   = 20
	dwmwaWindowCornerPreference = 33
	dwmwaCaptionColor           = 35
	dwmwaSystemBackdropType     = 38

	dwmwcpRound     = 2
	dwmsbtMainWindow = 2 // Mica
)

// applyWindows11Chrome configures native Windows 11 dark/light mode, rounded corners,
// caption color, and Mica backdrop on the given HWND.
func applyWindows11Chrome(hwnd uintptr, darkMode bool) {
	if hwnd == 0 {
		return
	}
	var dark uint32
	var captionColor uint32 = 0x00F3F3F3 // #F3F3F3 in COLORREF (0x00BBGGRR)
	if darkMode {
		dark = 1
		captionColor = 0x00202020 // #202020
	}
	corner := uint32(dwmwcpRound)
	backdrop := uint32(dwmsbtMainWindow)

	_, _, _ = procDwmSetWindowAttr.Call(hwnd, dwmwaUseImmersiveDarkMode, uintptr(unsafe.Pointer(&dark)), unsafe.Sizeof(dark))
	_, _, _ = procDwmSetWindowAttr.Call(hwnd, dwmwaWindowCornerPreference, uintptr(unsafe.Pointer(&corner)), unsafe.Sizeof(corner))
	_, _, _ = procDwmSetWindowAttr.Call(hwnd, dwmwaCaptionColor, uintptr(unsafe.Pointer(&captionColor)), unsafe.Sizeof(captionColor))
	_, _, _ = procDwmSetWindowAttr.Call(hwnd, dwmwaSystemBackdropType, uintptr(unsafe.Pointer(&backdrop)), unsafe.Sizeof(backdrop))

	if hIcon := tray.CreateSheriffBadgeIcon(tray.BadgeBrand); hIcon != 0 {
		_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, iconSmall, hIcon)
		_, _, _ = procSendMessageW.Call(hwnd, wmSetIcon, iconBig, hIcon)
	}
}

func focusWindowHandle(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	iconic, _, _ := procIsIconic.Call(hwnd)
	if iconic != 0 {
		_, _, _ = procShowWindow.Call(hwnd, swRestore)
	} else {
		_, _, _ = procShowWindow.Call(hwnd, swShow)
	}
	_, _, _ = procSetForegroundWindow.Call(hwnd)
}

// findCommandCenterWindows returns HWNDs of visible ShieldSheriff Command Center windows.
func findCommandCenterWindows() []uintptr {
	var found []uintptr

	cb := syscall.NewCallback(func(hwnd uintptr, lparam uintptr) uintptr {
		vis, _, _ := procIsWindowVisible.Call(hwnd)
		if vis == 0 {
			return 1
		}

		var titleBuf [256]uint16
		n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&titleBuf[0])), uintptr(len(titleBuf)))
		if n == 0 {
			return 1
		}
		title := syscall.UTF16ToString(titleBuf[:n])
		if title != "ShieldSheriff" && (!strings.Contains(title, "ShieldSheriff") || !strings.Contains(title, "Command Center")) {
			return 1
		}

		var classBuf [128]uint16
		cn, _, _ := procGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&classBuf[0])), uintptr(len(classBuf)))
		className := ""
		if cn > 0 {
			className = syscall.UTF16ToString(classBuf[:cn])
		}

		if className == "Chrome_WidgetWin_1" || title == "ShieldSheriff" || title == "ShieldSheriff - Command Center" {
			found = append(found, hwnd)
		}
		return 1
	})

	_, _, _ = procEnumWindows.Call(cb, 0)
	return found
}

// focusExistingCommandCenterWindow finds an already-open ShieldSheriff Command Center
// browser/app window and brings it to the foreground.
func focusExistingCommandCenterWindow() bool {
	wins := findCommandCenterWindows()
	if len(wins) == 0 {
		return false
	}
	focusWindowHandle(wins[0])
	return true
}

// closeExistingCommandCenterWindow posts WM_CLOSE to any open Command Center windows.
func closeExistingCommandCenterWindow() {
	for _, hwnd := range findCommandCenterWindows() {
		_, _, _ = procPostMessageW.Call(hwnd, wmClose, 0, 0)
	}
}
