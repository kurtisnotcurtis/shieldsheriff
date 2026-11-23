package defender

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Inspect reads the live Windows Defender and Security Center state using the default Windows Backend.
func Inspect(policy *Policy, pause *PauseState) Status {
	return InspectWith(DefaultBackend(), policy, pause)
}

// InspectWith reads live Windows Defender state using the supplied Backend.
// It is pure/read-only and works both elevated and unprivileged.
func InspectWith(b Backend, policy *Policy, pause *PauseState) Status {
	st := Status{
		InspectedAt: time.Now(),
		IsElevated:  b.IsElevated(),
	}

	// 1. Service & Platform Info
	if v, ok := b.ReadDword(HKLM, keyDefBase, "IsServiceRunning"); ok {
		st.ServiceRunning = (v == 1)
	} else {
		st.ServiceRunning = true
	}
	if v, ok := b.ReadDword(HKLM, keyDefBase, "PassiveMode"); ok && v == 1 {
		st.PassiveMode = true
	}
	if loc, _, ok := b.ReadString(HKLM, keyDefBase, "InstallLocation"); ok && loc != "" {
		cleaned := strings.TrimRight(loc, `\/`)
		st.PlatformVersion = filepath.Base(cleaned)
		candidate := filepath.Join(cleaned, "MpCmdRun.exe")
		if b.FileExists(candidate) {
			st.MpCmdRunPath = candidate
		}
	}
	if st.MpCmdRunPath == "" {
		fallback := `C:\Program Files\Windows Defender\MpCmdRun.exe`
		if b.FileExists(fallback) {
			st.MpCmdRunPath = fallback
		}
	}
	if sig, _, ok := b.ReadString(HKLM, keyDefSig, "AVSignatureVersion"); ok {
		st.SignatureVersion = sig
	}

	// 2. Tamper Protection
	// In Windows 11 Defender:
	// 0x0 or 0x4 = Disabled (bit 0 is 0)
	// 0x1 or 0x5 = Enabled  (bit 0 is 1)
	if tp, ok := b.ReadDword(HKLM, keyDefFeatures, "TamperProtection"); ok {
		st.TamperProtectionRaw = tp
		st.TamperProtectionActive = (tp & 0x1) != 0
	}
	if tps, ok := b.ReadDword(HKLM, keyDefFeatures, "TamperProtectionSource"); ok {
		st.TamperProtectionSource = tps
	}

	// 3. Real-Time Protection & Sub-Engines
	// Prefer live Defender engine keys when present so Inspect observes the engine's actual
	// state even if it ignored or reverted a Policy write. Fall back to Policy key only when
	// the live key is absent and Tamper Protection is OFF.
	effectiveBoolEngine := func(polKey, liveKey, valName string, defaultEnabled bool) (enabled bool, policyLocked bool) {
		polVal, hasPol := b.ReadDword(HKLM, polKey, valName)
		liveVal, hasLive := b.ReadDword(HKLM, liveKey, valName)
		if hasLive {
			// Value is named "Disable...", so 0 = Enabled, 1 = Disabled.
			enabled = (liveVal == 0)
		} else if hasPol && !st.TamperProtectionActive {
			enabled = (polVal == 0)
		} else {
			enabled = defaultEnabled
		}
		return enabled, hasPol
	}

	st.RealtimeProtection, st.PolicyRealtimeLocked = effectiveBoolEngine(keyPolRTP, keyDefRTP, "DisableRealtimeMonitoring", true)
	st.BehaviorMonitoring, _ = effectiveBoolEngine(keyPolRTP, keyDefRTP, "DisableBehaviorMonitoring", true)
	st.IOAVProtection, _ = effectiveBoolEngine(keyPolRTP, keyDefRTP, "DisableIOAVProtection", true)
	st.ScriptScanning, _ = effectiveBoolEngine(keyPolRTP, keyDefRTP, "DisableScriptScanning", true)

	// Network Protection (0 = Off, 1 = Enabled, 2 = Audit)
	if np, ok := b.ReadDword(HKLM, keyDefNetProt, "EnableNetworkProtection"); ok {
		st.NetworkProtection = np
	} else if npPol, okPol := b.ReadDword(HKLM, keyPolNetProt, "EnableNetworkProtection"); okPol && !st.TamperProtectionActive {
		st.NetworkProtection = npPol
	}

	// 4. Cloud-Delivered Protection (SpyNetReporting / MAPSReporting) & Sample Submission
	if cp, ok := b.ReadDword(HKLM, keyDefSpynet, "SpyNetReporting"); ok {
		st.CloudProtection = cp
	} else if cpPol, okPol := b.ReadDword(HKLM, keyPolSpynet, "SpynetReporting"); okPol && !st.TamperProtectionActive {
		st.CloudProtection = cpPol
	}
	_, st.PolicyCloudLocked = b.ReadDword(HKLM, keyPolSpynet, "SpynetReporting")

	if ss, ok := b.ReadDword(HKLM, keyDefSpynet, "SubmitSamplesConsent"); ok {
		st.SampleSubmission = ss
	} else if ssPol, okPol := b.ReadDword(HKLM, keyPolSpynet, "SubmitSamplesConsent"); okPol && !st.TamperProtectionActive {
		st.SampleSubmission = ssPol
	} else {
		st.SampleSubmission = 1 // Windows default is 1 (Send safe samples automatically)
	}
	_, st.PolicySamplesLocked = b.ReadDword(HKLM, keyPolSpynet, "SubmitSamplesConsent")

	// 5. Nag & Notification Layer
	disNotif, hasDisNotif := b.ReadDword(HKLM, keyPolWSCNotif, "DisableNotifications")
	disEnh, hasDisEnh := b.ReadDword(HKLM, keyPolWSCNotif, "DisableEnhancedNotifications")
	uxSupp, hasUxSupp := b.ReadDword(HKLM, keyDefUX, "Notification_Suppress")
	if !hasUxSupp {
		uxSupp, hasUxSupp = b.ReadDword(HKLM, keyPolUX, "Notification_Suppress")
	}

	st.EnhancedNagsSuppressed = hasDisEnh && disEnh == 1
	st.DefenderUXNagsSuppressed = hasUxSupp && uxSupp == 1
	st.NagsSuppressed = (hasDisNotif && disNotif == 1) && st.EnhancedNagsSuppressed

	hideTray, hasHideTray := b.ReadDword(HKLM, keyPolWSCSystray, "HideSystray")
	_, _, hasRunTray := b.ReadString(HKLM, keyWinRun, "SecurityHealth")
	st.SecurityTrayAutorunPresent = hasRunTray
	st.SecurityTrayIconMuted = (hasHideTray && hideTray == 1) || !hasRunTray

	// 6. Evaluate compliance against active Policy
	if policy != nil {
		st.InCompliance, st.DriftItems = EvaluateCompliance(st, *policy, pause)
	} else {
		st.InCompliance = true
	}

	return st
}

// EvaluateCompliance compares the live Status against the configured Policy and PauseState.
func EvaluateCompliance(st Status, policy Policy, pause *PauseState) (bool, []string) {
	var drift []string

	if st.TamperProtectionActive {
		drift = append(drift, "Tamper Protection is ON (blocks policy locks until toggled off once in Windows Security)")
	}

	expectedRTP := policy.RealtimeProtection
	if pause != nil && pause.Active {
		expectedRTP = false
	}
	if st.RealtimeProtection != expectedRTP {
		if expectedRTP {
			drift = append(drift, "Real-Time Protection is OFF (Expected: ON)")
		} else {
			drift = append(drift, "Real-Time Protection is ON (Expected: OFF)")
		}
	}

	if st.BehaviorMonitoring != policy.BehaviorMonitoring {
		drift = append(drift, fmt.Sprintf("Behavior Monitoring is %s (Expected: %s)", onOff(st.BehaviorMonitoring), onOff(policy.BehaviorMonitoring)))
	}
	if st.IOAVProtection != policy.IOAVProtection {
		drift = append(drift, fmt.Sprintf("Downloaded Files/Attachments Scan (IOAV) is %s (Expected: %s)", onOff(st.IOAVProtection), onOff(policy.IOAVProtection)))
	}
	if st.ScriptScanning != policy.ScriptScanning {
		drift = append(drift, fmt.Sprintf("Script Scanning is %s (Expected: %s)", onOff(st.ScriptScanning), onOff(policy.ScriptScanning)))
	}
	if st.NetworkProtection != policy.NetworkProtection {
		drift = append(drift, fmt.Sprintf("Network Protection is %d (Expected: %d)", st.NetworkProtection, policy.NetworkProtection))
	}
	if st.CloudProtection != policy.CloudProtection {
		drift = append(drift, fmt.Sprintf("Cloud-Delivered Protection is %s (Expected: %s)", cloudLabel(st.CloudProtection), cloudLabel(policy.CloudProtection)))
	}
	if st.SampleSubmission != policy.SampleSubmission {
		drift = append(drift, fmt.Sprintf("Automatic Sample Submission is %s (Expected: %s)", sampleLabel(st.SampleSubmission), sampleLabel(policy.SampleSubmission)))
	}
	if policy.SuppressAllNags && !st.NagsSuppressed {
		drift = append(drift, "Windows Security Nags are NOT suppressed (DisableNotifications / DisableEnhancedNotifications missing)")
	} else if !policy.SuppressAllNags && policy.SuppressEnhancedNags && !st.EnhancedNagsSuppressed {
		drift = append(drift, "Enhanced Nags are NOT suppressed (DisableEnhancedNotifications missing)")
	}
	if policy.MuteWindowsSecSystray && !st.SecurityTrayIconMuted {
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
