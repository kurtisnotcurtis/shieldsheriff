//go:build windows

package sheriff

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32Proc               = windows.NewLazySystemDLL("kernel32.dll")
	procQueryFullProcessImageName = modKernel32Proc.NewProc("QueryFullProcessImageNameW")
)

const processQueryLimitedInformation = 0x1000

// FindRunningWatchedProcess checks running processes via Win32 Toolhelp32 snapshot
// and returns the first watchList entry currently running.
// Entries without a path separator match the executable base name (e.g. "cargo.exe");
// entries containing "\" or "/" match the normalized full executable path suffix
// (e.g. "msvc\\bin\\link.exe") for stricter targeting.
func FindRunningWatchedProcess(watchList []string) string {
	if len(watchList) == 0 {
		return ""
	}

	nameSet := make(map[string]string)
	type pathTarget struct {
		suffix string
		orig   string
	}
	var pathTargets []pathTarget

	for _, w := range watchList {
		clean := strings.TrimSpace(strings.ToLower(w))
		if clean == "" {
			continue
		}
		if strings.ContainsAny(clean, `\/`) {
			norm := strings.ReplaceAll(clean, "/", `\`)
			if !strings.HasSuffix(norm, ".exe") {
				norm += ".exe"
			}
			pathTargets = append(pathTargets, pathTarget{suffix: norm, orig: w})
			continue
		}
		if !strings.HasSuffix(clean, ".exe") {
			clean += ".exe"
		}
		nameSet[clean] = w
	}
	if len(nameSet) == 0 && len(pathTargets) == 0 {
		return ""
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return ""
	}

	for {
		exeName := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		if orig, ok := nameSet[exeName]; ok {
			return orig
		}
		if len(pathTargets) > 0 {
			for _, pt := range pathTargets {
				if filepath.Base(pt.suffix) == exeName {
					if full := queryProcessImagePath(entry.ProcessID); full != "" {
						normFull := strings.ToLower(full)
						if normFull == pt.suffix || strings.HasSuffix(normFull, `\`+strings.TrimPrefix(pt.suffix, `\`)) {
							return pt.orig
						}
					}
				}
			}
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return ""
}

func queryProcessImagePath(pid uint32) string {
	h, err := windows.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var buf [windows.MAX_PATH * 2]uint16
	size := uint32(len(buf))
	r1, _, _ := procQueryFullProcessImageName.Call(
		uintptr(h),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 || size == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}
