//go:build windows

package ui

import (
	"syscall"
	"unsafe"

	"shieldsheriff/internal/tray"
)

var (
	modUser32               = syscall.NewLazyDLL("user32.dll")
	modDwmapi               = syscall.NewLazyDLL("dwmapi.dll")
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

	dwmwcpRound      = 2
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

func closeWindowHandle(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	_, _, _ = procPostMessageW.Call(hwnd, wmClose, 0, 0)
}
