package main

import (
	"fmt"
	"net/http"
	"syscall"
	"time"
	"unsafe"
)

var (
	modKernel32      = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW = modKernel32.NewProc("CreateMutexW")
)

const errorAlreadyExists = syscall.Errno(183)

// acquireSingleInstance creates a named Windows mutex to ensure only one interactive
// ShieldSheriff Command Center / tray instance runs per user session.
func acquireSingleInstance(name string) (release func(), alreadyRunning bool, err error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, false, err
	}
	handle, _, lastErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(namePtr)))
	if handle == 0 {
		return nil, false, lastErr
	}
	if lastErr == errorAlreadyExists {
		_ = syscall.CloseHandle(syscall.Handle(handle))
		return nil, true, nil
	}
	return func() {
		_ = syscall.CloseHandle(syscall.Handle(handle))
	}, false, nil
}

// focusExistingInstance asks an already-running interactive instance on preferredPort
// to open or bring its Command Center window to the foreground.
func focusExistingInstance(port int) bool {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%d/api/focus", port), "application/json", nil)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
