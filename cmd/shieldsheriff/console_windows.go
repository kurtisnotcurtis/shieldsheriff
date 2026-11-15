package main

import (
	"syscall"
	"unsafe"
)

var (
	modUser32Console        = syscall.NewLazyDLL("user32.dll")
	procGetConsoleWindow    = modKernel32.NewProc("GetConsoleWindow")
	procGetConsoleProcList  = modKernel32.NewProc("GetConsoleProcessList")
	procFreeConsole         = modKernel32.NewProc("FreeConsole")
	procShowWindowConsole   = modUser32Console.NewProc("ShowWindow")
)

const swHide = 0

// suppressOwnedConsoleWindow hides and detaches the console window when ShieldSheriff
// owns the console (for example when launched from Explorer, a shortcut, or UAC).
// When invoked from an existing interactive shell (count > 1), the shell window is left untouched.
func suppressOwnedConsoleWindow() bool {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return false
	}

	var pids [2]uint32
	count, _, _ := procGetConsoleProcList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if count != 1 {
		return false
	}

	_, _, _ = procShowWindowConsole.Call(hwnd, swHide)
	_, _, _ = procFreeConsole.Call()
	return true
}
