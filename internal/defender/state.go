package defender

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Mode is the single source of truth for whether ShieldSheriff is enforcing policies.
type Mode string

const (
	ModeUnconfigured Mode = "unconfigured"
	ModeActive       Mode = "active"
	ModePassive      Mode = "passive"
)

// Valid reports whether m is a recognized Mode value.
func (m Mode) Valid() bool {
	return m == ModeUnconfigured || m == ModeActive || m == ModePassive
}

// Status represents the live, inspected state of Windows Defender and the Windows Security notification layer.
type Status struct {
	InspectedAt time.Time `json:"inspectedAt"`
	IsElevated  bool      `json:"isElevated"`

	// Core Engine & Tamper Protection
	ServiceRunning         bool   `json:"serviceRunning"`
	PassiveMode            bool   `json:"passiveMode"`
	TamperProtectionActive bool   `json:"tamperProtectionActive"`
	TamperProtectionRaw    uint32 `json:"tamperProtectionRaw"`
	TamperProtectionSource uint32 `json:"tamperProtectionSource"`
	PlatformVersion        string `json:"platformVersion"`
	SignatureVersion       string `json:"signatureVersion"`
	MpCmdRunPath           string `json:"mpCmdRunPath"`

	// Granular Protection Engines (Live effective state)
	RealtimeProtection bool   `json:"realtimeProtection"`
	BehaviorMonitoring bool   `json:"behaviorMonitoring"`
	IOAVProtection     bool   `json:"ioavProtection"`
	ScriptScanning     bool   `json:"scriptScanning"`
	NetworkProtection  uint32 `json:"networkProtection"` // 0=Off, 1=Enabled (Block), 2=Audit

	// Cloud & Telemetry
	CloudProtection  uint32 `json:"cloudProtection"`  // MAPSReporting: 0=Off, 1=Basic, 2=Advanced
	SampleSubmission uint32 `json:"sampleSubmission"` // SubmitSamplesConsent: 0=Prompt, 1=Safe, 2=Never, 3=All

	// Policy Lock Status (Whether HKLM\SOFTWARE\Policies\Microsoft\Windows Defender locks are present)
	PolicyRealtimeLocked bool `json:"policyRealtimeLocked"`
	PolicyCloudLocked    bool `json:"policyCloudLocked"`
	PolicySamplesLocked  bool `json:"policySamplesLocked"`

	// Nag & Notification Layer Status
	NagsSuppressed             bool `json:"nagsSuppressed"`
	EnhancedNagsSuppressed     bool `json:"enhancedNagsSuppressed"`
	DefenderUXNagsSuppressed   bool `json:"defenderUxNagsSuppressed"`
	SecurityTrayIconMuted      bool `json:"securityTrayIconMuted"`
	SecurityTrayAutorunPresent bool `json:"securityTrayAutorunPresent"`

	// Compliance summary against active Policy
	InCompliance bool     `json:"inCompliance"`
	DriftItems   []string `json:"driftItems"`
}

// Policy defines the Windows Defender engine, cloud, notification, and auto-pause rules.
// App preferences (startup, auto-heal interval, update checks) and Mode live separately.
type Policy struct {
	PresetID string `json:"presetId"`

	// Granular Engine Toggles
	RealtimeProtection bool   `json:"realtimeProtection"`
	BehaviorMonitoring bool   `json:"behaviorMonitoring"`
	IOAVProtection     bool   `json:"ioavProtection"`
	ScriptScanning     bool   `json:"scriptScanning"`
	NetworkProtection  uint32 `json:"networkProtection"` // 0=Off, 1=Block, 2=Audit

	// Privacy & Cloud Toggles
	CloudProtection  uint32 `json:"cloudProtection"`  // 0=Off, 1=Basic, 2=Advanced
	SampleSubmission uint32 `json:"sampleSubmission"` // 0=Prompt, 1=Safe, 2=Never, 3=All

	// Notification & Tray Suppression
	SuppressAllNags       bool `json:"suppressAllNags"`
	SuppressEnhancedNags  bool `json:"suppressEnhancedNags"`
	MuteWindowsSecSystray bool `json:"muteWindowsSecSystray"`

	// Process-based Automatic Pause (pause Real-Time Protection while matching processes run)
	AutoPauseProcesses []string `json:"autoPauseProcesses"`
}

// Validate checks that all enumerated policy fields are within valid Windows Defender ranges.
func (p Policy) Validate() error {
	if p.NetworkProtection > 2 {
		return fmt.Errorf("invalid networkProtection value %d (expected 0=Off, 1=Block, or 2=Audit)", p.NetworkProtection)
	}
	if p.CloudProtection > 2 {
		return fmt.Errorf("invalid cloudProtection value %d (expected 0=Off, 1=Basic, or 2=Advanced)", p.CloudProtection)
	}
	if p.SampleSubmission > 3 {
		return fmt.Errorf("invalid sampleSubmission value %d (expected 0=Prompt, 1=Safe, 2=Never, or 3=All)", p.SampleSubmission)
	}
	return nil
}

// Clone returns a deep copy of Policy.
func (p Policy) Clone() Policy {
	cp := p
	if p.AutoPauseProcesses != nil {
		cp.AutoPauseProcesses = slices.Clone(p.AutoPauseProcesses)
	} else {
		cp.AutoPauseProcesses = []string{}
	}
	return cp
}

// Preferences holds application-level behavior independent of Defender presets.
type Preferences struct {
	AutoHeal            bool `json:"autoHeal"`
	DriftCheckSeconds   int  `json:"driftCheckSeconds"`
	StartupEnabled      bool `json:"startupEnabled"`
	CheckUpdatesOnStart bool `json:"checkUpdatesOnStart"`
}

// Normalize clamps Preferences fields to sane bounds.
func (p *Preferences) Normalize() {
	if p.DriftCheckSeconds < 10 {
		p.DriftCheckSeconds = 15
	}
	if p.DriftCheckSeconds > 86400 {
		p.DriftCheckSeconds = 86400
	}
}

// DefaultPreferences returns standard application preferences.
func DefaultPreferences() Preferences {
	return Preferences{
		AutoHeal:            true,
		DriftCheckSeconds:   15,
		StartupEnabled:      false,
		CheckUpdatesOnStart: false,
	}
}

// PauseState tracks a temporary pause of Real-Time Protection.
type PauseState struct {
	Active         bool      `json:"active"`
	Reason         string    `json:"reason"`
	StartedAt      time.Time `json:"startedAt,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt,omitempty"` // Zero if process-triggered only
	MatchedProcess string    `json:"matchedProcess,omitempty"`
}

// DefaultPolicy returns the default "Local Protection" policy:
// Real-Time local protection ON, Cloud lookup OFF, Automatic sample submission OFF (Never),
// and all Windows Security nagging notifications suppressed.
func DefaultPolicy() Policy {
	return Policy{
		PresetID:              "local-protection",
		RealtimeProtection:    true,
		BehaviorMonitoring:    true,
		IOAVProtection:        true,
		ScriptScanning:        true,
		NetworkProtection:     0,
		CloudProtection:       0, // Off
		SampleSubmission:      2, // Never send
		SuppressAllNags:       true,
		SuppressEnhancedNags:  true,
		MuteWindowsSecSystray: false,
		AutoPauseProcesses:    []string{},
	}
}

// Preset describes a named Policy template.
type Preset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ShortName   string `json:"shortName"`
	Description string `json:"description"`
	Policy      Policy `json:"policy"`
}

// BuiltinPresets returns ready-to-use configurations ordered from highest to lowest protection.
// This is the single source of truth for preset identity across CLI, UI, and System Tray.
func BuiltinPresets() []Preset {
	return []Preset{
		{
			ID:          "cloud-local",
			Name:        "Cloud + Local",
			ShortName:   "Cloud + Local",
			Description: "All local engines + Cloud Protection (MAPS) ON; automatic file sample uploads OFF; all Windows Security nags silenced.",
			Policy: Policy{
				PresetID:              "cloud-local",
				RealtimeProtection:    true,
				BehaviorMonitoring:    true,
				IOAVProtection:        true,
				ScriptScanning:        true,
				NetworkProtection:     1,
				CloudProtection:       2,
				SampleSubmission:      2,
				SuppressAllNags:       true,
				SuppressEnhancedNags:  true,
				MuteWindowsSecSystray: false,
				AutoPauseProcesses:    []string{},
			},
		},
		{
			ID:          "local-protection",
			Name:        "Local Protection (Recommended)",
			ShortName:   "Local Protection",
			Description: "Local Real-Time & Behavior protection ON; Cloud Protection & Sample Submission OFF; all Windows Security nags silenced.",
			Policy:      DefaultPolicy(),
		},
		{
			ID:          "workstation",
			Name:        "Workstation",
			ShortName:   "Workstation",
			Description: "File scan ON; Behavior Monitoring & Script Scanning OFF for fast builds; Cloud & Sample telemetry OFF; auto-pauses on cargo/msbuild/rustc.",
			Policy: Policy{
				PresetID:              "workstation",
				RealtimeProtection:    true,
				BehaviorMonitoring:    false,
				IOAVProtection:        true,
				ScriptScanning:        false,
				NetworkProtection:     0,
				CloudProtection:       0,
				SampleSubmission:      2,
				SuppressAllNags:       true,
				SuppressEnhancedNags:  true,
				MuteWindowsSecSystray: true,
				AutoPauseProcesses:    []string{"cargo.exe", "msbuild.exe", "rustc.exe"},
			},
		},
		{
			ID:          "on-demand",
			Name:        "On-Demand Only",
			ShortName:   "On-Demand Only",
			Description: "Real-Time Protection permanently OFF (no 24h auto-reset). Manual scans & signature updates remain active. All nags silenced.",
			Policy: Policy{
				PresetID:              "on-demand",
				RealtimeProtection:    false,
				BehaviorMonitoring:    false,
				IOAVProtection:        false,
				ScriptScanning:        false,
				NetworkProtection:     0,
				CloudProtection:       0,
				SampleSubmission:      2,
				SuppressAllNags:       true,
				SuppressEnhancedNags:  true,
				MuteWindowsSecSystray: true,
				AutoPauseProcesses:    []string{},
			},
		},
	}
}

// FindPreset looks up a built-in preset by ID (case-insensitive).
func FindPreset(id string) (Preset, bool) {
	needle := strings.ToLower(strings.TrimSpace(id))
	for _, p := range BuiltinPresets() {
		if p.ID == needle {
			p.Policy = p.Policy.Clone()
			return p, true
		}
	}
	return Preset{}, false
}

// PresetDisplayName returns the human-friendly short name for a preset ID.
func PresetDisplayName(id string) string {
	if p, ok := FindPreset(id); ok {
		return p.ShortName
	}
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "passive":
		return "Passive Mode"
	case "unconfigured", "":
		return "Not Configured"
	default:
		return "Custom"
	}
}

// PresetIDs returns all built-in preset IDs in canonical order.
func PresetIDs() []string {
	presets := BuiltinPresets()
	ids := make([]string, len(presets))
	for i, p := range presets {
		ids[i] = p.ID
	}
	return ids
}
