package defender

import "time"

// DeputyStatus represents the live, inspected state of Windows Defender ("The Deputy")
// and the Windows Security notification layer on this machine.
type DeputyStatus struct {
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

	// Cloud & Telemetry (The biggest nag triggers)
	CloudProtection  uint32 `json:"cloudProtection"`  // MAPSReporting: 0=Off, 1=Basic, 2=Advanced
	SampleSubmission uint32 `json:"sampleSubmission"` // SubmitSamplesConsent: 0=Prompt, 1=Safe, 2=Never, 3=All

	// Policy Lock Status (Whether HKLM\SOFTWARE\Policies\Microsoft\Windows Defender locks are present)
	PolicyRealtimeLocked bool `json:"policyRealtimeLocked"`
	PolicyCloudLocked    bool `json:"policyCloudLocked"`
	PolicySamplesLocked  bool `json:"policySamplesLocked"`

	// Nag & Notification Layer Status
	NagsSuppressed             bool `json:"nagsSuppressed"`             // DisableNotifications + DisableEnhancedNotifications + Notification_Suppress
	EnhancedNagsSuppressed     bool `json:"enhancedNagsSuppressed"`     // DisableEnhancedNotifications
	DefenderUXNagsSuppressed   bool `json:"defenderUxNagsSuppressed"`   // UX Configuration\Notification_Suppress
	SecurityTrayIconMuted      bool `json:"securityTrayIconMuted"`      // HideSystray or SecurityHealth Run removed
	SecurityTrayAutorunPresent bool `json:"securityTrayAutorunPresent"` // HKLM\...\Run\SecurityHealth exists

	// Drift summary against current StandingOrders
	InCompliance bool     `json:"inCompliance"`
	DriftItems   []string `json:"driftItems"`
}

// StandingOrders defines the user-elected rules that ShieldSheriff enforces on Windows Defender.
type StandingOrders struct {
	UpdatedAt           time.Time `json:"updatedAt"`
	PresetName          string    `json:"presetName"`
	Elected             bool      `json:"elected"`             // Whether ShieldSheriff is actively governing
	EnforceLoop         bool      `json:"enforceLoop"`         // Automatically revert Windows Update drift
	DriftCheckSeconds   int       `json:"driftCheckSeconds"`   // Auto-heal check interval in seconds (default 60)
	StartupEnabled      bool      `json:"startupEnabled"`      // Launch ShieldSheriff tray at Windows logon
	CheckUpdatesOnStart bool      `json:"checkUpdatesOnStart"` // Check GitHub releases on startup

	// Granular Deputy Engine Toggles
	RealtimeProtection bool   `json:"realtimeProtection"`
	BehaviorMonitoring bool   `json:"behaviorMonitoring"`
	IOAVProtection     bool   `json:"ioavProtection"`
	ScriptScanning     bool   `json:"scriptScanning"`
	NetworkProtection  uint32 `json:"networkProtection"` // 0=Off, 1=Block, 2=Audit

	// Privacy & Cloud Toggles
	CloudProtection  uint32 `json:"cloudProtection"`  // 0=Off (recommended for nag-free privacy), 1=Basic, 2=Advanced
	SampleSubmission uint32 `json:"sampleSubmission"` // 2=Never Send (recommended), 1=Safe samples, 3=All

	// Keep the Peace (Nag & Tray Suppression)
	SuppressAllNags       bool `json:"suppressAllNags"`       // Silence Security Center & Defender toast nags
	SuppressEnhancedNags  bool `json:"suppressEnhancedNags"`  // Silence Cloud/Sample/Tamper "recommendation" nags
	MuteWindowsSecSystray bool `json:"muteWindowsSecSystray"` // Hide default nagging Windows Security tray icon

	// Process-based Automatic Stand-Down (pause Real-Time Protection while these processes run)
	AutoStandDownProcesses []string `json:"autoStandDownProcesses"`
}

// StandDownState tracks a temporary pause of Real-Time Protection ("Deputy Stand-Down").
type StandDownState struct {
	Active          bool      `json:"active"`
	Reason          string    `json:"reason"`          // e.g. "Timer (30m)" or "Process active: cargo.exe"
	StartedAt       time.Time `json:"startedAt"`
	ExpiresAt       time.Time `json:"expiresAt"`       // Zero if process-triggered only
	MatchedProcess  string    `json:"matchedProcess"`  // Non-empty if triggered by a watched process
}

// DefaultStandingOrders returns the signature "Quiet Guardian" configuration:
// Real-Time local protection ON, Cloud lookup OFF, Automatic sample submission OFF (Never),
// and all Windows Security nagging notifications suppressed.
func DefaultStandingOrders() StandingOrders {
	return StandingOrders{
		UpdatedAt:              time.Now(),
		PresetName:             "quiet-guardian",
		Elected:                true,
		EnforceLoop:            true,
		DriftCheckSeconds:      15,
		RealtimeProtection:     true,
		BehaviorMonitoring:     true,
		IOAVProtection:         true,
		ScriptScanning:         true,
		NetworkProtection:      0,
		CloudProtection:        0, // Off
		SampleSubmission:       2, // Never send
		SuppressAllNags:        true,
		SuppressEnhancedNags:   true,
		MuteWindowsSecSystray:  false,
		AutoStandDownProcesses: []string{},
	}
}

// Preset describes a named StandingOrders template.
type Preset struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Orders      StandingOrders `json:"orders"`
}

// BuiltinPresets returns ready-to-use configurations for common workflows.
func BuiltinPresets() []Preset {
	return []Preset{
		{
			ID:          "quiet-guardian",
			Name:        "Quiet Guardian (Recommended)",
			Description: "Local Real-Time & Behavior protection ON; Cloud Protection & Sample Submission OFF; all Windows Security nags silenced.",
			Orders:      DefaultStandingOrders(),
		},
		{
			ID:          "dev-workstation",
			Name:        "Developer Workstation",
			Description: "File scan ON, heavy Behavioral & Script hooks OFF for fast builds, Cloud & Sample telemetry OFF, auto-pause on cargo/msbuild/go.",
			Orders: StandingOrders{
				UpdatedAt:              time.Now(),
				PresetName:             "dev-workstation",
				Elected:                true,
				EnforceLoop:            true,
				RealtimeProtection:     true,
				BehaviorMonitoring:     false,
				IOAVProtection:         true,
				ScriptScanning:         false,
				NetworkProtection:      0,
				CloudProtection:        0,
				SampleSubmission:       2,
				SuppressAllNags:        true,
				SuppressEnhancedNags:   true,
				MuteWindowsSecSystray:  true,
				AutoStandDownProcesses: []string{"cargo.exe", "msbuild.exe", "link.exe", "rustc.exe"},
			},
		},
		{
			ID:          "on-demand-only",
			Name:        "On-Demand Only (Zero Background Overhead)",
			Description: "Real-Time Protection permanently OFF (no 24h auto-reset). Manual scans & signature updates remain active. All nags silenced.",
			Orders: StandingOrders{
				UpdatedAt:              time.Now(),
				PresetName:             "on-demand-only",
				Elected:                true,
				EnforceLoop:            true,
				RealtimeProtection:     false,
				BehaviorMonitoring:     false,
				IOAVProtection:         false,
				ScriptScanning:         false,
				NetworkProtection:      0,
				CloudProtection:        0,
				SampleSubmission:       2,
				SuppressAllNags:        true,
				SuppressEnhancedNags:   true,
				MuteWindowsSecSystray:  true,
				AutoStandDownProcesses: []string{},
			},
		},
		{
			ID:          "full-shield-no-nag",
			Name:        "Full Local + Cloud Shield (Nag-Free)",
			Description: "All local engines + Cloud lookup ON, automatic file sample uploads OFF, security nags silenced.",
			Orders: StandingOrders{
				UpdatedAt:              time.Now(),
				PresetName:             "full-shield-no-nag",
				Elected:                true,
				EnforceLoop:            true,
				RealtimeProtection:     true,
				BehaviorMonitoring:     true,
				IOAVProtection:         true,
				ScriptScanning:         true,
				NetworkProtection:      1,
				CloudProtection:        2,
				SampleSubmission:       2,
				SuppressAllNags:        true,
				SuppressEnhancedNags:   true,
				MuteWindowsSecSystray:  false,
				AutoStandDownProcesses: []string{},
			},
		},
	}
}
