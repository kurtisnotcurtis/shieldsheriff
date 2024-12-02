package defender

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	procRegOpenKeyExW    = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegCreateKeyExW  = modAdvapi32.NewProc("RegCreateKeyExW")
	procRegQueryValueExW = modAdvapi32.NewProc("RegQueryValueExW")
	procRegSetValueExW   = modAdvapi32.NewProc("RegSetValueExW")
	procRegDeleteValueW  = modAdvapi32.NewProc("RegDeleteValueW")
	procRegCloseKey      = modAdvapi32.NewProc("RegCloseKey")
)

const (
	hkeyLocalMachine = uintptr(0x80000002)
	hkeyCurrentUser  = uintptr(0x80000001)

	keyRead        = 0x20019
	keyWrite       = 0x20006
	keyAllAccess   = 0xF003F
	keyWow6464Key  = 0x0100

	regSz       = 1
	regExpandSz = 2
	regDword    = 4
)

func regReadDword(root uintptr, subkey, valueName string) (uint32, bool) {
	subkeyPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return 0, false
	}
	var hKey uintptr
	ret, _, _ := procRegOpenKeyExW.Call(
		root,
		uintptr(unsafe.Pointer(subkeyPtr)),
		0,
		keyRead|keyWow6464Key,
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return 0, false
	}
	defer procRegCloseKey.Call(hKey)

	valPtr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return 0, false
	}
	var valType uint32
	var data uint32
	dataLen := uint32(4)
	ret, _, _ = procRegQueryValueExW.Call(
		hKey,
		uintptr(unsafe.Pointer(valPtr)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if ret != 0 || valType != regDword {
		return 0, false
	}
	return data, true
}

func regReadString(root uintptr, subkey, valueName string) (string, bool) {
	subkeyPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return "", false
	}
	var hKey uintptr
	ret, _, _ := procRegOpenKeyExW.Call(
		root,
		uintptr(unsafe.Pointer(subkeyPtr)),
		0,
		keyRead|keyWow6464Key,
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return "", false
	}
	defer procRegCloseKey.Call(hKey)

	valPtr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return "", false
	}
	var valType uint32
	var dataLen uint32
	ret, _, _ = procRegQueryValueExW.Call(
		hKey,
		uintptr(unsafe.Pointer(valPtr)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		0,
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if ret != 0 || dataLen == 0 || (valType != regSz && valType != regExpandSz) {
		return "", false
	}

	buf := make([]uint16, dataLen/2+1)
	ret, _, _ = procRegQueryValueExW.Call(
		hKey,
		uintptr(unsafe.Pointer(valPtr)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if ret != 0 {
		return "", false
	}
	return syscall.UTF16ToString(buf), true
}

// Inspect reads the live Windows Defender and Security Center state from the Registry and filesystem.
// It works both with and without Administrator privileges.
func Inspect(orders *StandingOrders, standDown *StandDownState) DeputyStatus {
	st := DeputyStatus{
		InspectedAt: time.Now(),
		IsElevated:  IsProcessElevated(),
	}

	const (
		defBase     = `SOFTWARE\Microsoft\Windows Defender`
		defFeatures = `SOFTWARE\Microsoft\Windows Defender\Features`
		defRTP      = `SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`
		defSpynet   = `SOFTWARE\Microsoft\Windows Defender\Spynet`
		defSig      = `SOFTWARE\Microsoft\Windows Defender\Signature Updates`
		defNetProt  = `SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`
		defUX       = `SOFTWARE\Microsoft\Windows Defender\UX Configuration`

		polBase    = `SOFTWARE\Policies\Microsoft\Windows Defender`
		polRTP     = `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
		polSpynet  = `SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`
		polNetProt = `SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`
		polUX      = `SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration`

		polWSCNotif   = `SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications`
		polWSCSystray = `SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray`
		winRunKey     = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	)

	// 1. Service & Platform Info
	if v, ok := regReadDword(hkeyLocalMachine, defBase, "IsServiceRunning"); ok {
		st.ServiceRunning = (v == 1)
	} else {
		st.ServiceRunning = true
	}
	if v, ok := regReadDword(hkeyLocalMachine, defBase, "PassiveMode"); ok && v == 1 {
		st.PassiveMode = true
	}
	if loc, ok := regReadString(hkeyLocalMachine, defBase, "InstallLocation"); ok && loc != "" {
		cleaned := strings.TrimRight(loc, `\/`)
		st.PlatformVersion = filepath.Base(cleaned)
		candidate := filepath.Join(cleaned, "MpCmdRun.exe")
		if _, err := os.Stat(candidate); err == nil {
			st.MpCmdRunPath = candidate
		}
	}
	if st.MpCmdRunPath == "" {
		fallback := `C:\Program Files\Windows Defender\MpCmdRun.exe`
		if _, err := os.Stat(fallback); err == nil {
			st.MpCmdRunPath = fallback
		}
	}
	if sig, ok := regReadString(hkeyLocalMachine, defSig, "AVSignatureVersion"); ok {
		st.SignatureVersion = sig
	}

	// 2. Tamper Protection
	if tp, ok := regReadDword(hkeyLocalMachine, defFeatures, "TamperProtection"); ok {
		st.TamperProtectionRaw = tp
		st.TamperProtectionActive = (tp == 1)
	}
	if tps, ok := regReadDword(hkeyLocalMachine, defFeatures, "TamperProtectionSource"); ok {
		st.TamperProtectionSource = tps
	}

	// 3. Real-Time Protection & Sub-Engines (effective state = Policy override if TamperProtection is off, else live key)
	effectiveBoolEngine := func(polKey, liveKey, valName string, defaultEnabled bool) (enabled bool, policyLocked bool) {
		polVal, hasPol := regReadDword(hkeyLocalMachine, polKey, valName)
		liveVal, hasLive := regReadDword(hkeyLocalMachine, liveKey, valName)
		if hasLive {
			// Value is named "Disable...", so 0 = Enabled, 1 = Disabled
			enabled = (liveVal == 0)
		} else if hasPol && !st.TamperProtectionActive {
			enabled = (polVal == 0)
		} else {
			enabled = defaultEnabled
		}
		return enabled, hasPol
	}

	st.RealtimeProtection, st.PolicyRealtimeLocked = effectiveBoolEngine(polRTP, defRTP, "DisableRealtimeMonitoring", true)
	st.BehaviorMonitoring, _ = effectiveBoolEngine(polRTP, defRTP, "DisableBehaviorMonitoring", true)
	st.IOAVProtection, _ = effectiveBoolEngine(polRTP, defRTP, "DisableIOAVProtection", true)
	st.ScriptScanning, _ = effectiveBoolEngine(polRTP, defRTP, "DisableScriptScanning", true)

	// Network Protection (0 = Off, 1 = Enabled, 2 = Audit)
	if np, ok := regReadDword(hkeyLocalMachine, defNetProt, "EnableNetworkProtection"); ok {
		st.NetworkProtection = np
	} else if npPol, okPol := regReadDword(hkeyLocalMachine, polNetProt, "EnableNetworkProtection"); okPol {
		st.NetworkProtection = npPol
	}

	// 4. Cloud-Delivered Protection (SpyNetReporting / MAPSReporting) & Sample Submission
	if cp, ok := regReadDword(hkeyLocalMachine, defSpynet, "SpyNetReporting"); ok {
		st.CloudProtection = cp
	} else if cpPol, okPol := regReadDword(hkeyLocalMachine, polSpynet, "SpynetReporting"); okPol {
		st.CloudProtection = cpPol
	}
	_, st.PolicyCloudLocked = regReadDword(hkeyLocalMachine, polSpynet, "SpynetReporting")

	if ss, ok := regReadDword(hkeyLocalMachine, defSpynet, "SubmitSamplesConsent"); ok {
		st.SampleSubmission = ss
	} else if ssPol, okPol := regReadDword(hkeyLocalMachine, polSpynet, "SubmitSamplesConsent"); okPol {
		st.SampleSubmission = ssPol
	} else {
		st.SampleSubmission = 1 // Windows default is 1 (Send safe samples automatically)
	}
	_, st.PolicySamplesLocked = regReadDword(hkeyLocalMachine, polSpynet, "SubmitSamplesConsent")

	// 5. Nag & Notification Layer
	disNotif, hasDisNotif := regReadDword(hkeyLocalMachine, polWSCNotif, "DisableNotifications")
	disEnh, hasDisEnh := regReadDword(hkeyLocalMachine, polWSCNotif, "DisableEnhancedNotifications")
	uxSupp, hasUxSupp := regReadDword(hkeyLocalMachine, polUX, "Notification_Suppress")
	if !hasUxSupp {
		uxSupp, hasUxSupp = regReadDword(hkeyLocalMachine, defUX, "Notification_Suppress")
	}

	st.EnhancedNagsSuppressed = hasDisEnh && disEnh == 1
	st.DefenderUXNagsSuppressed = hasUxSupp && uxSupp == 1
	st.NagsSuppressed = (hasDisNotif && disNotif == 1) && st.EnhancedNagsSuppressed

	hideTray, hasHideTray := regReadDword(hkeyLocalMachine, polWSCSystray, "HideSystray")
	_, hasRunTray := regReadString(hkeyLocalMachine, winRunKey, "SecurityHealth")
	st.SecurityTrayAutorunPresent = hasRunTray
	st.SecurityTrayIconMuted = (hasHideTray && hideTray == 1) || !hasRunTray

	// 6. Evaluate compliance against StandingOrders
	if orders != nil {
		st.InCompliance, st.DriftItems = EvaluateCompliance(st, *orders, standDown)
	} else {
		st.InCompliance = true
	}

	return st
}

// EvaluateCompliance compares the live DeputyStatus against the user's StandingOrders.
func EvaluateCompliance(st DeputyStatus, orders StandingOrders, standDown *StandDownState) (bool, []string) {
	var drift []string

	if st.TamperProtectionActive {
		drift = append(drift, "Tamper Protection is ON (blocks policy locks until toggled off once in Windows Security)")
	}

	expectedRTP := orders.RealtimeProtection
	if standDown != nil && standDown.Active {
		expectedRTP = false
	}
	if st.RealtimeProtection != expectedRTP {
		if expectedRTP {
			drift = append(drift, "Real-Time Protection is OFF (Standing Order: ON)")
		} else {
			drift = append(drift, "Real-Time Protection is ON (Standing Order: OFF)")
		}
	}

	if st.BehaviorMonitoring != orders.BehaviorMonitoring {
		drift = append(drift, fmt.Sprintf("Behavior Monitoring is %s (Standing Order: %s)", onOff(st.BehaviorMonitoring), onOff(orders.BehaviorMonitoring)))
	}
	if st.IOAVProtection != orders.IOAVProtection {
		drift = append(drift, fmt.Sprintf("Downloaded Files/Attachments Scan (IOAV) is %s (Standing Order: %s)", onOff(st.IOAVProtection), onOff(orders.IOAVProtection)))
	}
	if st.ScriptScanning != orders.ScriptScanning {
		drift = append(drift, fmt.Sprintf("Script Scanning is %s (Standing Order: %s)", onOff(st.ScriptScanning), onOff(orders.ScriptScanning)))
	}
	if st.NetworkProtection != orders.NetworkProtection {
		drift = append(drift, fmt.Sprintf("Network Protection is %d (Standing Order: %d)", st.NetworkProtection, orders.NetworkProtection))
	}
	if st.CloudProtection != orders.CloudProtection {
		drift = append(drift, fmt.Sprintf("Cloud-Delivered Protection is %s (Standing Order: %s)", cloudLabel(st.CloudProtection), cloudLabel(orders.CloudProtection)))
	}
	if st.SampleSubmission != orders.SampleSubmission {
		drift = append(drift, fmt.Sprintf("Automatic Sample Submission is %s (Standing Order: %s)", sampleLabel(st.SampleSubmission), sampleLabel(orders.SampleSubmission)))
	}
	if orders.SuppressAllNags && !st.NagsSuppressed {
		drift = append(drift, "Windows Security Nags are NOT suppressed (DisableNotifications / DisableEnhancedNotifications missing)")
	} else if !orders.SuppressAllNags && orders.SuppressEnhancedNags && !st.EnhancedNagsSuppressed {
		drift = append(drift, "Enhanced Nags are NOT suppressed (DisableEnhancedNotifications missing)")
	}
	if orders.MuteWindowsSecSystray && !st.SecurityTrayIconMuted {
		drift = append(drift, "Default Windows Security Tray Icon is still active")
	}

	return len(drift) == 0, drift
}

func onOff(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

func cloudLabel(v uint32) string {
	switch v {
	case 0:
		return "OFF (0)"
	case 1:
		return "Basic (1)"
	case 2:
		return "Advanced (2)"
	default:
		return fmt.Sprintf("Unknown (%d)", v)
	}
}

func sampleLabel(v uint32) string {
	switch v {
	case 0:
		return "Always Prompt (0)"
	case 1:
		return "Send Safe Samples (1)"
	case 2:
		return "Never Send / OFF (2)"
	case 3:
		return "Send All Samples (3)"
	default:
		return fmt.Sprintf("Unknown (%d)", v)
	}
}
