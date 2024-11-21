package defender

import "time"

// DeputyStatus represents the live, inspected state of Windows Defender ("The Deputy").
type DeputyStatus struct {
	InspectedAt time.Time `json:"inspectedAt"`
	IsElevated  bool      `json:"isElevated"`

	ServiceRunning         bool   `json:"serviceRunning"`
	PassiveMode            bool   `json:"passiveMode"`
	TamperProtectionActive bool   `json:"tamperProtectionActive"`
	TamperProtectionRaw    uint32 `json:"tamperProtectionRaw"`
	TamperProtectionSource uint32 `json:"tamperProtectionSource"`
	PlatformVersion        string `json:"platformVersion"`
	SignatureVersion       string `json:"signatureVersion"`
	MpCmdRunPath           string `json:"mpCmdRunPath"`

	RealtimeProtection bool   `json:"realtimeProtection"`
	BehaviorMonitoring bool   `json:"behaviorMonitoring"`
	IOAVProtection     bool   `json:"ioavProtection"`
	ScriptScanning     bool   `json:"scriptScanning"`
	NetworkProtection  uint32 `json:"networkProtection"`

	CloudProtection  uint32 `json:"cloudProtection"`
	SampleSubmission uint32 `json:"sampleSubmission"`

	PolicyRealtimeLocked bool `json:"policyRealtimeLocked"`
	PolicyCloudLocked    bool `json:"policyCloudLocked"`
	PolicySamplesLocked  bool `json:"policySamplesLocked"`

	InCompliance bool     `json:"inCompliance"`
	DriftItems   []string `json:"driftItems"`
}

// StandingOrders defines the user-elected rules that ShieldSheriff enforces on Windows Defender.
type StandingOrders struct {
	UpdatedAt   time.Time `json:"updatedAt"`
	PresetName  string    `json:"presetName"`
	Elected     bool      `json:"elected"`
	EnforceLoop bool      `json:"enforceLoop"`

	RealtimeProtection bool   `json:"realtimeProtection"`
	BehaviorMonitoring bool   `json:"behaviorMonitoring"`
	IOAVProtection     bool   `json:"ioavProtection"`
	ScriptScanning     bool   `json:"scriptScanning"`
	NetworkProtection  uint32 `json:"networkProtection"`

	CloudProtection  uint32 `json:"cloudProtection"`
	SampleSubmission uint32 `json:"sampleSubmission"`
}

func DefaultStandingOrders() StandingOrders {
	return StandingOrders{
		UpdatedAt:          time.Now(),
		PresetName:         "quiet-guardian",
		Elected:            true,
		EnforceLoop:        true,
		RealtimeProtection: true,
		BehaviorMonitoring: true,
		IOAVProtection:     true,
		ScriptScanning:     true,
		NetworkProtection:  0,
		CloudProtection:    0,
		SampleSubmission:   2,
	}
}
