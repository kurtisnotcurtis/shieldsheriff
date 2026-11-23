package defender

import (
	"context"
	"fmt"
	"time"
)

const (
	wmiSyncTimeout   = 15 * time.Second
	taskkillTimeout  = 5 * time.Second
	quickScanTimeout = 10 * time.Minute
	sigUpdateTimeout = 2 * time.Minute
)

// EnforceResult reports the outcome of applying or reverting Defender policies.
type EnforceResult struct {
	Success  bool     `json:"success"`
	Applied  []string `json:"applied"`
	Warnings []string `json:"warnings"`
}

type dwordWrite struct {
	root   RegRoot
	subkey string
	name   string
	val    uint32
	label  string // optional human-readable Applied summary
}

// Enforce applies the Policy (and optional PauseState override) using the default Windows Backend.
func Enforce(policy Policy, pause *PauseState) EnforceResult {
	return EnforceWith(DefaultBackend(), policy, pause)
}

// EnforceWith applies Policy via Group Policy keys, live Defender keys, and PowerShell DCOM Set-MpPreference.
// All registry write errors are tracked and propagated; Success is false if any required write fails.
func EnforceWith(b Backend, policy Policy, pause *PauseState) EnforceResult {
	res := EnforceResult{Success: true}

	if err := policy.Validate(); err != nil {
		res.Success = false
		res.Warnings = append(res.Warnings, err.Error())
		return res
	}
	if !b.IsElevated() {
		res.Success = false
		res.Warnings = append(res.Warnings, "Administrator privileges required to enforce Defender policies")
		return res
	}

	if err := CaptureSnapshotIfMissing(b); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("Failed to capture pre-change registry snapshot: %v", err))
	}

	effectiveRTP := policy.RealtimeProtection
	if pause != nil && pause.Active {
		effectiveRTP = false
	}

	boolToDis := func(enabled bool) uint32 {
		if enabled {
			return 0 // Disable* = 0 means Enabled
		}
		return 1 // Disable* = 1 means Disabled
	}

	disRTP := boolToDis(effectiveRTP)
	disBM := boolToDis(policy.BehaviorMonitoring)
	disIOAV := boolToDis(policy.IOAVProtection)
	disScript := boolToDis(policy.ScriptScanning)
	var disScanOnEnable uint32
	if !effectiveRTP {
		disScanOnEnable = 1
	}
	var disBlockFirstSeen uint32
	if policy.CloudProtection == 0 {
		disBlockFirstSeen = 1
	}

	var disNotif, disEnhNotif, notifSuppress, toastEnabled uint32
	if policy.SuppressAllNags {
		disNotif = 1
		disEnhNotif = 1
		notifSuppress = 1
		toastEnabled = 0
	} else {
		disNotif = 0
		notifSuppress = 0
		toastEnabled = 1
		if policy.SuppressEnhancedNags {
			disEnhNotif = 1
		}
	}

	var hideSystray uint32
	if policy.MuteWindowsSecSystray {
		hideSystray = 1
	}

	writes := []dwordWrite{
		// Keep Defender service alive so on-demand scans and signature updates remain available
		{HKLM, keyPolBase, "DisableAntiSpyware", 0, ""},
		{HKLM, keyPolBase, "DisableAntiVirus", 0, ""},

		// Notifications & Security Center nags
		{HKLM, keyPolWSCNotif, "DisableNotifications", disNotif, fmt.Sprintf("Policy DisableNotifications=%d", disNotif)},
		{HKLM, keyPolWSCNotif, "DisableEnhancedNotifications", disEnhNotif, fmt.Sprintf("Policy DisableEnhancedNotifications=%d", disEnhNotif)},
		{HKLM, keyPolUX, "Notification_Suppress", notifSuppress, ""},
		{HKLM, keyDefUX, "Notification_Suppress", notifSuppress, ""},
		{HKCU, keyToastSec, "Enabled", toastEnabled, ""},
		{HKLM, keyPolWSCSystray, "HideSystray", hideSystray, fmt.Sprintf("Policy HideSystray=%d", hideSystray)},

		// Granular Engine Policy Locks
		{HKLM, keyPolRTP, "DisableRealtimeMonitoring", disRTP, fmt.Sprintf("Policy DisableRealtimeMonitoring=%d", disRTP)},
		{HKLM, keyPolRTP, "DisableBehaviorMonitoring", disBM, fmt.Sprintf("Policy DisableBehaviorMonitoring=%d", disBM)},
		{HKLM, keyPolRTP, "DisableIOAVProtection", disIOAV, fmt.Sprintf("Policy DisableIOAVProtection=%d", disIOAV)},
		{HKLM, keyPolRTP, "DisableScriptScanning", disScript, fmt.Sprintf("Policy DisableScriptScanning=%d", disScript)},
		{HKLM, keyPolRTP, "DisableScanOnRealtimeEnable", disScanOnEnable, ""},

		// Cloud & Sample Policy Locks
		{HKLM, keyPolSpynet, "SpynetReporting", policy.CloudProtection, fmt.Sprintf("Policy SpynetReporting=%d", policy.CloudProtection)},
		{HKLM, keyPolSpynet, "SubmitSamplesConsent", policy.SampleSubmission, fmt.Sprintf("Policy SubmitSamplesConsent=%d", policy.SampleSubmission)},
		{HKLM, keyPolSpynet, "DisableBlockAtFirstSeen", disBlockFirstSeen, ""},

		// Network Protection Policy Lock
		{HKLM, keyPolNetProt, "EnableNetworkProtection", policy.NetworkProtection, fmt.Sprintf("Policy EnableNetworkProtection=%d", policy.NetworkProtection)},
	}

	for _, w := range writes {
		if err := b.WriteDword(w.root, w.subkey, w.name, w.val); err != nil {
			res.Success = false
			res.Warnings = append(res.Warnings, err.Error())
			continue
		}
		if w.label != "" {
			res.Applied = append(res.Applied, w.label)
		}
	}

	// Windows Security Systray Run entry
	if policy.MuteWindowsSecSystray {
		if err := b.DeleteValue(HKLM, keyWinRun, "SecurityHealth"); err != nil {
			res.Success = false
			res.Warnings = append(res.Warnings, err.Error())
		} else {
			res.Applied = append(res.Applied, "Muted Windows Security tray autorun")
		}
		ctx, cancel := context.WithTimeout(context.Background(), taskkillTimeout)
		_, _ = b.RunCommand(ctx, "taskkill.exe", "/F", "/IM", "SecurityHealthSystray.exe")
		cancel()
	} else {
		if _, _, ok := b.ReadString(HKLM, keyWinRun, "SecurityHealth"); !ok {
			restoreVal := defaultSecurityHealthRun
			if snap, hasSnap, _ := loadSnapshot(b); hasSnap {
				runID := managedRegSpec{HKLM, keyWinRun, "SecurityHealth", RegExpandSZ}.keyID()
				if e, ok := snap.Entries[runID]; ok && e.Exists && e.StringVal != "" {
					restoreVal = e.StringVal
				}
			}
			if err := b.WriteString(HKLM, keyWinRun, "SecurityHealth", restoreVal, RegExpandSZ); err != nil {
				res.Warnings = append(res.Warnings, err.Error())
			}
		}
	}

	// Direct Live Defender Keys (succeeds when Tamper Protection is OFF; failures recorded as warnings)
	liveWrites := []dwordWrite{
		{HKLM, keyDefRTP, "DisableRealtimeMonitoring", disRTP, ""},
		{HKLM, keyDefRTP, "DisableBehaviorMonitoring", disBM, ""},
		{HKLM, keyDefRTP, "DisableIOAVProtection", disIOAV, ""},
		{HKLM, keyDefRTP, "DisableScriptScanning", disScript, ""},
		{HKLM, keyDefSpynet, "SpyNetReporting", policy.CloudProtection, ""},
		{HKLM, keyDefSpynet, "SubmitSamplesConsent", policy.SampleSubmission, ""},
		{HKLM, keyDefNetProt, "EnableNetworkProtection", policy.NetworkProtection, ""},
	}
	liveWriteFailed := false
	for _, w := range liveWrites {
		if err := b.WriteDword(w.root, w.subkey, w.name, w.val); err != nil {
			liveWriteFailed = true
			res.Warnings = append(res.Warnings, fmt.Sprintf("Live key write failed (%s\\%s): %v", w.subkey, w.name, err))
		}
	}

	// Live WMI MSFT_MpPreference sync via PowerShell DCOM CimSession (bounded by timeout)
	if err := syncWMIPreferences(b, effectiveRTP, policy); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("WMI live sync failed: %v", err))
		if liveWriteFailed {
			res.Success = false
		}
	} else {
		res.Applied = append(res.Applied, "Synchronized live Defender engine via DCOM Set-MpPreference")
	}

	return res
}

func syncWMIPreferences(b Backend, effectiveRTP bool, policy Policy) error {
	psBool := func(v bool) string {
		if v {
			return "$true"
		}
		return "$false"
	}

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
		psBool(!policy.BehaviorMonitoring),
		psBool(!policy.IOAVProtection),
		psBool(!policy.ScriptScanning),
		policy.CloudProtection,
		policy.SampleSubmission,
		policy.NetworkProtection,
	)

	ctx, cancel := context.WithTimeout(context.Background(), wmiSyncTimeout)
	defer cancel()

	out, err := b.RunCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	if err != nil {
		if out != "" {
			return fmt.Errorf("%w (%s)", err, out)
		}
		return err
	}
	return nil
}

// RevertPolicies restores all Defender and Security Center registry values modified by ShieldSheriff
// using the default Windows Backend.
func RevertPolicies() EnforceResult {
	return RevertPoliciesWith(DefaultBackend())
}

// RevertPoliciesWith restores every managed registry key to its pre-ShieldSheriff snapshot
// (or Windows defaults if no snapshot exists) and syncs the live engine via DCOM Set-MpPreference.
func RevertPoliciesWith(b Backend) EnforceResult {
	res := EnforceResult{Success: true}
	if !b.IsElevated() {
		res.Success = false
		res.Warnings = append(res.Warnings, "Administrator privileges required to revert policies")
		return res
	}

	snap, hasSnap, snapErr := loadSnapshot(b)
	if snapErr != nil {
		res.Warnings = append(res.Warnings, snapErr.Error())
	}

	restoredCount := 0
	for _, spec := range managedRegistryValues {
		if hasSnap {
			entry, known := snap.Entries[spec.keyID()]
			if known {
				if entry.Exists {
					var err error
					if entry.Kind == RegDword || spec.Kind == RegDword {
						err = b.WriteDword(spec.Root, spec.Subkey, spec.Name, entry.DwordVal)
					} else {
						kind := entry.Kind
						if kind == 0 {
							kind = spec.Kind
						}
						err = b.WriteString(spec.Root, spec.Subkey, spec.Name, entry.StringVal, kind)
					}
					if err != nil {
						res.Success = false
						res.Warnings = append(res.Warnings, fmt.Sprintf("Restore %s: %v", spec.keyID(), err))
					} else {
						restoredCount++
					}
					continue
				}
				// Value did not exist before ShieldSheriff ran -> delete it
				if err := b.DeleteValue(spec.Root, spec.Subkey, spec.Name); err != nil {
					res.Success = false
					res.Warnings = append(res.Warnings, fmt.Sprintf("Delete %s: %v", spec.keyID(), err))
				} else {
					restoredCount++
				}
				continue
			}
		}

		// Fallback when no pre-change snapshot exists: remove policy/live overrides and restore notifications/tray.
		switch {
		case spec.Root == HKCU && spec.Subkey == keyToastSec && spec.Name == "Enabled":
			if err := b.WriteDword(spec.Root, spec.Subkey, spec.Name, 1); err != nil {
				res.Success = false
				res.Warnings = append(res.Warnings, err.Error())
			} else {
				restoredCount++
			}
		case spec.Root == HKLM && spec.Subkey == keyWinRun && spec.Name == "SecurityHealth":
			if _, _, ok := b.ReadString(HKLM, keyWinRun, "SecurityHealth"); !ok {
				val := defaultSecurityHealthRun
				if legacy, _, ok := b.ReadString(HKLM, keyBackup, valLegacyRunBk); ok && legacy != "" {
					val = legacy
				}
				if err := b.WriteString(HKLM, keyWinRun, "SecurityHealth", val, RegExpandSZ); err != nil {
					res.Success = false
					res.Warnings = append(res.Warnings, err.Error())
				} else {
					restoredCount++
				}
			}
		default:
			if err := b.DeleteValue(spec.Root, spec.Subkey, spec.Name); err != nil {
				res.Success = false
				res.Warnings = append(res.Warnings, err.Error())
			} else {
				restoredCount++
			}
		}
	}

	// Sync live Defender engine back to the restored/default values so MsMpEng reflects the revert immediately.
	restoredPolicy := policyFromRestoredState(b)
	if err := syncWMIPreferences(b, restoredPolicy.RealtimeProtection, restoredPolicy); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("WMI revert sync note: %v", err))
	} else {
		res.Applied = append(res.Applied, "Synchronized reverted Defender preferences via DCOM Set-MpPreference")
	}

	if res.Success && hasSnap {
		_ = b.DeleteValue(HKLM, keyBackup, valBackupSnap)
	}

	if res.Success {
		res.Applied = append(res.Applied, fmt.Sprintf("Reverted %d ShieldSheriff registry setting(s) to pre-ShieldSheriff state", restoredCount))
	}
	return res
}

func policyFromRestoredState(b Backend) Policy {
	st := InspectWith(b, nil, nil)
	return Policy{
		RealtimeProtection: st.RealtimeProtection,
		BehaviorMonitoring: st.BehaviorMonitoring,
		IOAVProtection:     st.IOAVProtection,
		ScriptScanning:     st.ScriptScanning,
		NetworkProtection:  st.NetworkProtection,
		CloudProtection:    st.CloudProtection,
		SampleSubmission:   st.SampleSubmission,
	}
}

// RunQuickScan triggers an on-demand Quick Scan using Defender's native MpCmdRun.exe.
func RunQuickScan() (string, error) {
	return RunQuickScanWith(DefaultBackend())
}

// RunQuickScanWith triggers a Quick Scan using the supplied Backend with a bounded timeout.
func RunQuickScanWith(b Backend) (string, error) {
	st := InspectWith(b, nil, nil)
	if st.MpCmdRunPath == "" {
		return "", fmt.Errorf("MpCmdRun.exe not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), quickScanTimeout)
	defer cancel()
	return b.RunCommand(ctx, st.MpCmdRunPath, "-Scan", "-ScanType", "1")
}

// UpdateSignatures triggers an immediate virus definition update via MpCmdRun.exe.
func UpdateSignatures() (string, error) {
	return UpdateSignaturesWith(DefaultBackend())
}

// UpdateSignaturesWith triggers a definition update using the supplied Backend with a bounded timeout.
func UpdateSignaturesWith(b Backend) (string, error) {
	st := InspectWith(b, nil, nil)
	if st.MpCmdRunPath == "" {
		return "", fmt.Errorf("MpCmdRun.exe not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), sigUpdateTimeout)
	defer cancel()
	return b.RunCommand(ctx, st.MpCmdRunPath, "-SignatureUpdate")
}
