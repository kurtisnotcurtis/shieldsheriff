package defender

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

func regWriteDword(root uintptr, subkey, valueName string, val uint32) error {
	subkeyPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	var hKey uintptr
	var disposition uint32
	ret, _, _ := procRegCreateKeyExW.Call(
		root,
		uintptr(unsafe.Pointer(subkeyPtr)),
		0,
		0,
		0,
		keyWrite|keyWow6464Key,
		0,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if ret != 0 {
		return fmt.Errorf("RegCreateKeyExW(%s) failed with code %d", subkey, ret)
	}
	defer procRegCloseKey.Call(hKey)

	valPtr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return err
	}
	ret, _, _ = procRegSetValueExW.Call(
		hKey,
		uintptr(unsafe.Pointer(valPtr)),
		0,
		regDword,
		uintptr(unsafe.Pointer(&val)),
		4,
	)
	if ret != 0 {
		return fmt.Errorf("RegSetValueExW(%s\\%s) failed with code %d", subkey, valueName, ret)
	}
	return nil
}

func regWriteString(root uintptr, subkey, valueName string, val string, valType uint32) error {
	subkeyPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	var hKey uintptr
	var disposition uint32
	ret, _, _ := procRegCreateKeyExW.Call(
		root,
		uintptr(unsafe.Pointer(subkeyPtr)),
		0,
		0,
		0,
		keyWrite|keyWow6464Key,
		0,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if ret != 0 {
		return fmt.Errorf("RegCreateKeyExW(%s) failed with code %d", subkey, ret)
	}
	defer procRegCloseKey.Call(hKey)

	valPtr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return err
	}
	utf16Slice, err := syscall.UTF16FromString(val)
	if err != nil {
		return err
	}
	byteLen := uint32(len(utf16Slice) * 2)
	ret, _, _ = procRegSetValueExW.Call(
		hKey,
		uintptr(unsafe.Pointer(valPtr)),
		0,
		uintptr(valType),
		uintptr(unsafe.Pointer(&utf16Slice[0])),
		uintptr(byteLen),
	)
	if ret != 0 {
		return fmt.Errorf("RegSetValueExW(%s\\%s) failed with code %d", subkey, valueName, ret)
	}
	return nil
}

func regDeleteVal(root uintptr, subkey, valueName string) error {
	subkeyPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}
	var hKey uintptr
	ret, _, _ := procRegOpenKeyExW.Call(
		root,
		uintptr(unsafe.Pointer(subkeyPtr)),
		0,
		keyWrite|keyWow6464Key,
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return nil // Key doesn't exist
	}
	defer procRegCloseKey.Call(hKey)

	valPtr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return err
	}
	ret, _, _ = procRegDeleteValueW.Call(hKey, uintptr(unsafe.Pointer(valPtr)))
	if ret != 0 && ret != 2 { // 2 = ERROR_FILE_NOT_FOUND
		return fmt.Errorf("RegDeleteValueW(%s\\%s) failed with code %d", subkey, valueName, ret)
	}
	return nil
}

// EnforceResult reports the outcome of applying StandingOrders.
type EnforceResult struct {
	Success  bool     `json:"success"`
	Applied  []string `json:"applied"`
	Warnings []string `json:"warnings"`
}

// Enforce applies the StandingOrders (and optional StandDownState override) to:
//  1. Windows Group Policy keys (HKLM\SOFTWARE\Policies\Microsoft\Windows Defender & Windows Defender Security Center)
//  2. Windows Defender live keys (HKLM\SOFTWARE\Microsoft\Windows Defender)
//  3. Live WMI MSFT_MpPreference via DCOM CimSession so MsMpEng.exe reloads immediately
func Enforce(orders StandingOrders, standDown *StandDownState) EnforceResult {
	res := EnforceResult{Success: true}

	if !IsProcessElevated() {
		res.Success = false
		res.Warnings = append(res.Warnings, "Process is not elevated (Administrator / SYSTEM required to enforce policies)")
		return res
	}

	const (
		polBase       = `SOFTWARE\Policies\Microsoft\Windows Defender`
		polRTP        = `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
		polSpynet     = `SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`
		polNetProt    = `SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`
		polUX         = `SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration`
		polWSCNotif   = `SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications`
		polWSCSystray = `SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray`

		defRTP     = `SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`
		defSpynet  = `SOFTWARE\Microsoft\Windows Defender\Spynet`
		defNetProt = `SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`
		defUX      = `SOFTWARE\Microsoft\Windows Defender\UX Configuration`

		winRunKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
		sheriffBack = `SOFTWARE\ShieldSheriff\Backup`
		toastSecKey = `Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance`
	)

	effectiveRTP := orders.RealtimeProtection
	if standDown != nil && standDown.Active {
		effectiveRTP = false
	}

	boolToDisDword := func(enabled bool) uint32 {
		if enabled {
			return 0 // Disable* = 0 means Enabled
		}
		return 1 // Disable* = 1 means Disabled
	}

	// 1. Keep Defender Service Alive (Never set DisableAntiSpyware=1, so on-demand scans & updates stay alive)
	_ = regWriteDword(hkeyLocalMachine, polBase, "DisableAntiSpyware", 0)
	_ = regWriteDword(hkeyLocalMachine, polBase, "DisableAntiVirus", 0)

	// 2. Nag & Notification Suppression (Works even if Tamper Protection is still ON!)
	if orders.SuppressAllNags {
		if err := regWriteDword(hkeyLocalMachine, polWSCNotif, "DisableNotifications", 1); err == nil {
			res.Applied = append(res.Applied, "Suppressed Windows Security Center Toast Notifications (DisableNotifications=1)")
		} else {
			res.Warnings = append(res.Warnings, err.Error())
		}
		if err := regWriteDword(hkeyLocalMachine, polWSCNotif, "DisableEnhancedNotifications", 1); err == nil {
			res.Applied = append(res.Applied, "Suppressed Cloud/Sample/Tamper Nags (DisableEnhancedNotifications=1)")
		}
		_ = regWriteDword(hkeyLocalMachine, polUX, "Notification_Suppress", 1)
		_ = regWriteDword(hkeyLocalMachine, defUX, "Notification_Suppress", 1)
		_ = regWriteDword(hkeyCurrentUser, toastSecKey, "Enabled", 0)
	} else {
		_ = regWriteDword(hkeyLocalMachine, polWSCNotif, "DisableNotifications", 0)
		_ = regWriteDword(hkeyLocalMachine, polUX, "Notification_Suppress", 0)
		_ = regWriteDword(hkeyCurrentUser, toastSecKey, "Enabled", 1)
		if orders.SuppressEnhancedNags {
			_ = regWriteDword(hkeyLocalMachine, polWSCNotif, "DisableEnhancedNotifications", 1)
			res.Applied = append(res.Applied, "Suppressed Non-Critical Enhanced Nags (DisableEnhancedNotifications=1)")
		} else {
			_ = regWriteDword(hkeyLocalMachine, polWSCNotif, "DisableEnhancedNotifications", 0)
		}
	}

	// 3. Windows Security Systray Icon Muting
	if orders.MuteWindowsSecSystray {
		_ = regWriteDword(hkeyLocalMachine, polWSCSystray, "HideSystray", 1)
		if curRun, ok := regReadString(hkeyLocalMachine, winRunKey, "SecurityHealth"); ok && curRun != "" {
			_ = regWriteString(hkeyLocalMachine, sheriffBack, "SecurityHealthRun", curRun, regExpandSz)
			_ = regDeleteVal(hkeyLocalMachine, winRunKey, "SecurityHealth")
		}
		// Gently stop running SecurityHealthSystray.exe if active
		killCmd := exec.Command("taskkill.exe", "/F", "/IM", "SecurityHealthSystray.exe")
		killCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		_ = killCmd.Run()
		res.Applied = append(res.Applied, "Muted Windows Security default tray icon (HideSystray=1)")
	} else {
		_ = regWriteDword(hkeyLocalMachine, polWSCSystray, "HideSystray", 0)
		if _, ok := regReadString(hkeyLocalMachine, winRunKey, "SecurityHealth"); !ok {
			backupVal, hasBackup := regReadString(hkeyLocalMachine, sheriffBack, "SecurityHealthRun")
			if !hasBackup || backupVal == "" {
				backupVal = `%windir%\system32\SecurityHealthSystray.exe`
			}
			_ = regWriteString(hkeyLocalMachine, winRunKey, "SecurityHealth", backupVal, regExpandSz)
		}
	}

	// 4. Granular Engine Policy Locks (HKLM\SOFTWARE\Policies\Microsoft\Windows Defender)
	disRTP := boolToDisDword(effectiveRTP)
	disBM := boolToDisDword(orders.BehaviorMonitoring)
	disIOAV := boolToDisDword(orders.IOAVProtection)
	disScript := boolToDisDword(orders.ScriptScanning)

	if err := regWriteDword(hkeyLocalMachine, polRTP, "DisableRealtimeMonitoring", disRTP); err == nil {
		res.Applied = append(res.Applied, fmt.Sprintf("Policy DisableRealtimeMonitoring=%d", disRTP))
	}
	_ = regWriteDword(hkeyLocalMachine, polRTP, "DisableBehaviorMonitoring", disBM)
	_ = regWriteDword(hkeyLocalMachine, polRTP, "DisableIOAVProtection", disIOAV)
	_ = regWriteDword(hkeyLocalMachine, polRTP, "DisableScriptScanning", disScript)
	if !effectiveRTP {
		_ = regWriteDword(hkeyLocalMachine, polRTP, "DisableScanOnRealtimeEnable", 1)
	} else {
		_ = regWriteDword(hkeyLocalMachine, polRTP, "DisableScanOnRealtimeEnable", 0)
	}

	// Cloud & Sample Policy Locks
	_ = regWriteDword(hkeyLocalMachine, polSpynet, "SpynetReporting", orders.CloudProtection)
	_ = regWriteDword(hkeyLocalMachine, polSpynet, "SubmitSamplesConsent", orders.SampleSubmission)
	if orders.CloudProtection == 0 {
		_ = regWriteDword(hkeyLocalMachine, polSpynet, "DisableBlockAtFirstSeen", 1)
	} else {
		_ = regWriteDword(hkeyLocalMachine, polSpynet, "DisableBlockAtFirstSeen", 0)
	}
	res.Applied = append(res.Applied, fmt.Sprintf("Policy SpynetReporting=%d, SubmitSamplesConsent=%d", orders.CloudProtection, orders.SampleSubmission))

	// Network Protection Policy Lock
	_ = regWriteDword(hkeyLocalMachine, polNetProt, "EnableNetworkProtection", orders.NetworkProtection)

	// 5. Direct Live Engine Registry Keys (succeeds when Tamper Protection is OFF)
	_ = regWriteDword(hkeyLocalMachine, defRTP, "DisableRealtimeMonitoring", disRTP)
	_ = regWriteDword(hkeyLocalMachine, defRTP, "DisableBehaviorMonitoring", disBM)
	_ = regWriteDword(hkeyLocalMachine, defRTP, "DisableIOAVProtection", disIOAV)
	_ = regWriteDword(hkeyLocalMachine, defRTP, "DisableScriptScanning", disScript)
	_ = regWriteDword(hkeyLocalMachine, defSpynet, "SpyNetReporting", orders.CloudProtection)
	_ = regWriteDword(hkeyLocalMachine, defSpynet, "SubmitSamplesConsent", orders.SampleSubmission)
	_ = regWriteDword(hkeyLocalMachine, defNetProt, "EnableNetworkProtection", orders.NetworkProtection)

	// 6. Live WMI MSFT_MpPreference Sync via DCOM CimSession (works even when WinRM/WSMan is off)
	if err := syncWMIPreferences(effectiveRTP, orders); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("WMI live sync note: %v (Policy registry locks are still applied)", err))
	} else {
		res.Applied = append(res.Applied, "Synchronized live MsMpEng.exe engine via WMI (MSFT_MpPreference)")
	}

	return res
}

func syncWMIPreferences(effectiveRTP bool, orders StandingOrders) error {
	psBool := func(b bool) string {
		if b {
			return "$true"
		}
		return "$false"
	}

	// Build a single fast PowerShell command using DCOM CimSession so it never fails on disabled WSMan
	script := fmt.Sprintf(
		`$ErrorActionPreference = 'Stop'; `+
			`$opt = New-CimSessionOption -Protocol Dcom; `+
			`$s = New-CimSession -SessionOption $opt; `+
			`try { `+
			`Set-MpPreference -CimSession $s `+
			`-DisableRealtimeMonitoring %s `+
			`-DisableBehaviorMonitoring %s `+
			`-DisableIOAVProtection %s `+
			`-DisableScriptScanning %s `+
			`-MAPSReporting %d `+
			`-SubmitSamplesConsent %d `+
			`-EnableNetworkProtection %d `+
			`} finally { Remove-CimSession $s -ErrorAction SilentlyContinue }`,
		psBool(!effectiveRTP),
		psBool(!orders.BehaviorMonitoring),
		psBool(!orders.IOAVProtection),
		psBool(!orders.ScriptScanning),
		orders.CloudProtection,
		orders.SampleSubmission,
		orders.NetworkProtection,
	)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RunQuickScan triggers an on-demand Quick Scan using Defender's native MpCmdRun.exe.
// This works even when Real-Time Protection is turned OFF!
func RunQuickScan() (string, error) {
	st := Inspect(nil, nil)
	if st.MpCmdRunPath == "" {
		return "", fmt.Errorf("MpCmdRun.exe not found")
	}
	cmd := exec.Command(st.MpCmdRunPath, "-Scan", "-ScanType", "1")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// UpdateSignatures triggers an immediate virus definition update via MpCmdRun.exe.
func UpdateSignatures() (string, error) {
	st := Inspect(nil, nil)
	if st.MpCmdRunPath == "" {
		return "", fmt.Errorf("MpCmdRun.exe not found")
	}
	cmd := exec.Command(st.MpCmdRunPath, "-SignatureUpdate")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
