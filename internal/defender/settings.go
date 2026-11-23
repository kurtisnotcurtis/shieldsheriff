package defender

import (
	"encoding/json"
	"fmt"
)

// Canonical Windows Registry paths used by Inspect, Enforce, Snapshot, and Revert.
// Declared once here so Enforce and Revert can never drift apart.
const (
	keyDefBase     = `SOFTWARE\Microsoft\Windows Defender`
	keyDefFeatures = `SOFTWARE\Microsoft\Windows Defender\Features`
	keyDefRTP      = `SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`
	keyDefSpynet   = `SOFTWARE\Microsoft\Windows Defender\Spynet`
	keyDefSig      = `SOFTWARE\Microsoft\Windows Defender\Signature Updates`
	keyDefNetProt  = `SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`
	keyDefUX       = `SOFTWARE\Microsoft\Windows Defender\UX Configuration`

	keyPolBase    = `SOFTWARE\Policies\Microsoft\Windows Defender`
	keyPolRTP     = `SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
	keyPolSpynet  = `SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`
	keyPolNetProt = `SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`
	keyPolUX      = `SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration`

	keyPolWSCNotif   = `SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications`
	keyPolWSCSystray = `SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray`

	keyWinRun      = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	keyBackup      = `SOFTWARE\ShieldSheriff\Backup`
	keyToastSec    = `Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance`
	valBackupSnap  = "SnapshotJSON"
	valLegacyRunBk = "SecurityHealthRun"
)

const defaultSecurityHealthRun = `%windir%\system32\SecurityHealthSystray.exe`

// managedRegSpec identifies every registry value written by Enforce so Snapshot and Revert
// cover the exact same set of keys.
type managedRegSpec struct {
	Root   RegRoot
	Subkey string
	Name   string
	Kind   RegValueKind
}

func (m managedRegSpec) keyID() string {
	rootStr := "HKLM"
	if m.Root == HKCU {
		rootStr = "HKCU"
	}
	return rootStr + `\` + m.Subkey + `\` + m.Name
}

// managedRegistryValues lists every single registry value that Enforce can modify.
var managedRegistryValues = []managedRegSpec{
	// Group Policy keys
	{HKLM, keyPolBase, "DisableAntiSpyware", RegDword},
	{HKLM, keyPolBase, "DisableAntiVirus", RegDword},
	{HKLM, keyPolRTP, "DisableRealtimeMonitoring", RegDword},
	{HKLM, keyPolRTP, "DisableBehaviorMonitoring", RegDword},
	{HKLM, keyPolRTP, "DisableIOAVProtection", RegDword},
	{HKLM, keyPolRTP, "DisableScriptScanning", RegDword},
	{HKLM, keyPolRTP, "DisableScanOnRealtimeEnable", RegDword},
	{HKLM, keyPolSpynet, "SpynetReporting", RegDword},
	{HKLM, keyPolSpynet, "SubmitSamplesConsent", RegDword},
	{HKLM, keyPolSpynet, "DisableBlockAtFirstSeen", RegDword},
	{HKLM, keyPolNetProt, "EnableNetworkProtection", RegDword},
	{HKLM, keyPolUX, "Notification_Suppress", RegDword},
	{HKLM, keyPolWSCNotif, "DisableNotifications", RegDword},
	{HKLM, keyPolWSCNotif, "DisableEnhancedNotifications", RegDword},
	{HKLM, keyPolWSCSystray, "HideSystray", RegDword},

	// Live Defender keys
	{HKLM, keyDefRTP, "DisableRealtimeMonitoring", RegDword},
	{HKLM, keyDefRTP, "DisableBehaviorMonitoring", RegDword},
	{HKLM, keyDefRTP, "DisableIOAVProtection", RegDword},
	{HKLM, keyDefRTP, "DisableScriptScanning", RegDword},
	{HKLM, keyDefSpynet, "SpyNetReporting", RegDword},
	{HKLM, keyDefSpynet, "SubmitSamplesConsent", RegDword},
	{HKLM, keyDefNetProt, "EnableNetworkProtection", RegDword},
	{HKLM, keyDefUX, "Notification_Suppress", RegDword},

	// User toast notification & tray autorun
	{HKCU, keyToastSec, "Enabled", RegDword},
	{HKLM, keyWinRun, "SecurityHealth", RegExpandSZ},
}

type regSnapshotEntry struct {
	Exists    bool         `json:"exists"`
	Kind      RegValueKind `json:"kind,omitempty"`
	DwordVal  uint32       `json:"dwordVal,omitempty"`
	StringVal string       `json:"stringVal,omitempty"`
}

type regSnapshot struct {
	Entries map[string]regSnapshotEntry `json:"entries"`
}

// CaptureSnapshotIfMissing saves the pre-ShieldSheriff values of all managed registry keys
// on first apply so Passive Mode can truly revert every change.
func CaptureSnapshotIfMissing(b Backend) error {
	if raw, _, ok := b.ReadString(HKLM, keyBackup, valBackupSnap); ok && raw != "" {
		return nil
	}

	snap := regSnapshot{Entries: make(map[string]regSnapshotEntry, len(managedRegistryValues))}
	for _, spec := range managedRegistryValues {
		var entry regSnapshotEntry
		if spec.Kind == RegDword {
			if v, ok := b.ReadDword(spec.Root, spec.Subkey, spec.Name); ok {
				entry = regSnapshotEntry{Exists: true, Kind: RegDword, DwordVal: v}
			}
		} else {
			if v, k, ok := b.ReadString(spec.Root, spec.Subkey, spec.Name); ok {
				entry = regSnapshotEntry{Exists: true, Kind: k, StringVal: v}
			}
		}
		snap.Entries[spec.keyID()] = entry
	}

	// Preserve legacy SecurityHealthRun backup if a previous version already hid the Run entry.
	runID := managedRegSpec{HKLM, keyWinRun, "SecurityHealth", RegExpandSZ}.keyID()
	if !snap.Entries[runID].Exists {
		if legacy, _, ok := b.ReadString(HKLM, keyBackup, valLegacyRunBk); ok && legacy != "" {
			snap.Entries[runID] = regSnapshotEntry{Exists: true, Kind: RegExpandSZ, StringVal: legacy}
		}
	}

	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal registry snapshot: %w", err)
	}
	return b.WriteString(HKLM, keyBackup, valBackupSnap, string(data), RegSZ)
}

// loadSnapshot reads the saved pre-ShieldSheriff snapshot if present.
func loadSnapshot(b Backend) (*regSnapshot, bool, error) {
	raw, _, ok := b.ReadString(HKLM, keyBackup, valBackupSnap)
	if !ok || raw == "" {
		return nil, false, nil
	}
	var snap regSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		return nil, false, fmt.Errorf("parse registry snapshot: %w", err)
	}
	return &snap, true, nil
}
