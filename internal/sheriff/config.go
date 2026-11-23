package sheriff

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"shieldsheriff/internal/defender"
)

const (
	ConfigSchemaVersion = 2
	configFileName      = "config.json"
)

// AuditEntry records an action taken by ShieldSheriff.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Category  string    `json:"category"` // "INIT", "APPLY", "ENFORCE", "DRIFT", "PAUSE", "PASSIVE", "STARTUP", "UPDATE", "WARN"
	Message   string    `json:"message"`
}

// Config is the persisted single source of truth stored in config.json.
// It separates Mode, Defender Policy, App Preferences, and active PauseState.
type Config struct {
	SchemaVersion int                  `json:"schemaVersion"`
	UpdatedAt     time.Time            `json:"updatedAt"`
	Mode          defender.Mode        `json:"mode"`
	Policy        defender.Policy      `json:"policy"`
	Preferences   defender.Preferences `json:"preferences"`
	Pause         defender.PauseState  `json:"pause"`
}

// Clone returns a deep copy of Config.
func (c Config) Clone() Config {
	cp := c
	cp.Policy = c.Policy.Clone()
	return cp
}

// Validate checks that Mode and Policy contain valid values.
func (c Config) Validate() error {
	if !c.Mode.Valid() {
		return fmt.Errorf("invalid mode %q (expected unconfigured, active, or passive)", c.Mode)
	}
	return c.Policy.Validate()
}

// DefaultConfig returns a new unconfigured Config with default preferences.
func DefaultConfig() Config {
	return Config{
		SchemaVersion: ConfigSchemaVersion,
		UpdatedAt:     time.Now(),
		Mode:          defender.ModeUnconfigured,
		Policy:        defender.DefaultPolicy(),
		Preferences:   defender.DefaultPreferences(),
	}
}

// ConfigPath returns the canonical path to config.json.
// Prefers %ProgramData%\ShieldSheriff\config.json when elevated or when it already exists,
// falling back to %LOCALAPPDATA%\ShieldSheriff\config.json for unprivileged reads.
func ConfigPath() string {
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	sysPath := filepath.Join(progData, "ShieldSheriff", configFileName)

	if defender.IsProcessElevated() {
		return sysPath
	}
	if _, err := os.Stat(sysPath); err == nil {
		return sysPath
	}

	localApp := os.Getenv("LOCALAPPDATA")
	if localApp != "" {
		return filepath.Join(localApp, "ShieldSheriff", configFileName)
	}
	exe, err := os.Executable()
	if err == nil {
		return filepath.Join(filepath.Dir(exe), configFileName)
	}
	return configFileName
}

// legacyV1Config captures the pre-v2 flat StandingOrders JSON schema for transparent migration.
type legacyV1Config struct {
	UpdatedAt              time.Time `json:"updatedAt"`
	PresetName             string    `json:"presetName"`
	Elected                bool      `json:"elected"`
	EnforceLoop            bool      `json:"enforceLoop"`
	DriftCheckSeconds      int       `json:"driftCheckSeconds"`
	StartupEnabled         bool      `json:"startupEnabled"`
	CheckUpdatesOnStart    bool      `json:"checkUpdatesOnStart"`
	RealtimeProtection     bool      `json:"realtimeProtection"`
	BehaviorMonitoring     bool      `json:"behaviorMonitoring"`
	IOAVProtection         bool      `json:"ioavProtection"`
	ScriptScanning         bool      `json:"scriptScanning"`
	NetworkProtection      uint32    `json:"networkProtection"`
	CloudProtection        uint32    `json:"cloudProtection"`
	SampleSubmission       uint32    `json:"sampleSubmission"`
	SuppressAllNags        bool      `json:"suppressAllNags"`
	SuppressEnhancedNags   bool      `json:"suppressEnhancedNags"`
	MuteWindowsSecSystray  bool      `json:"muteWindowsSecSystray"`
	AutoStandDownProcesses []string  `json:"autoStandDownProcesses"`
}

// LoadConfig reads config.json from the default ConfigPath().
func LoadConfig() (Config, string, error) {
	path := ConfigPath()
	cfg, err := LoadConfigFrom(path)
	return cfg, path, err
}

// LoadConfigFrom reads and validates a Config from the specified file path.
// If the file does not exist, it returns a wrapped os.ErrNotExist so callers can
// distinguish genuine first-run from corrupt or unreadable files.
// Legacy v1 flat StandingOrders files are automatically migrated in memory.
func LoadConfigFrom(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultConfig(), err
	}

	var probe struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return DefaultConfig(), fmt.Errorf("parse %s: %w", path, err)
	}

	var cfg Config
	if probe.SchemaVersion >= ConfigSchemaVersion {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return DefaultConfig(), fmt.Errorf("decode v%d config %s: %w", probe.SchemaVersion, path, err)
		}
	} else {
		var old legacyV1Config
		if err := json.Unmarshal(data, &old); err != nil {
			return DefaultConfig(), fmt.Errorf("decode legacy config %s: %w", path, err)
		}
		mode := defender.ModeUnconfigured
		if old.Elected {
			mode = defender.ModeActive
		} else if old.PresetName == "passive" {
			mode = defender.ModePassive
		}
		presetID := old.PresetName
		if presetID == "passive" || presetID == "unconfigured" {
			presetID = ""
		}
		procs := old.AutoStandDownProcesses
		if procs == nil {
			procs = []string{}
		}
		cfg = Config{
			SchemaVersion: ConfigSchemaVersion,
			UpdatedAt:     old.UpdatedAt,
			Mode:          mode,
			Policy: defender.Policy{
				PresetID:              presetID,
				RealtimeProtection:    old.RealtimeProtection,
				BehaviorMonitoring:    old.BehaviorMonitoring,
				IOAVProtection:        old.IOAVProtection,
				ScriptScanning:        old.ScriptScanning,
				NetworkProtection:     old.NetworkProtection,
				CloudProtection:       old.CloudProtection,
				SampleSubmission:      old.SampleSubmission,
				SuppressAllNags:       old.SuppressAllNags,
				SuppressEnhancedNags:  old.SuppressEnhancedNags,
				MuteWindowsSecSystray: old.MuteWindowsSecSystray,
				AutoPauseProcesses:    procs,
			},
			Preferences: defender.Preferences{
				AutoHeal:            old.EnforceLoop,
				DriftCheckSeconds:   old.DriftCheckSeconds,
				StartupEnabled:      old.StartupEnabled,
				CheckUpdatesOnStart: old.CheckUpdatesOnStart,
			},
		}
	}

	if cfg.Policy.AutoPauseProcesses == nil {
		cfg.Policy.AutoPauseProcesses = []string{}
	}
	cfg.SchemaVersion = ConfigSchemaVersion
	cfg.Preferences.Normalize()
	if err := cfg.Validate(); err != nil {
		return DefaultConfig(), fmt.Errorf("invalid config in %s: %w", path, err)
	}
	return cfg, nil
}

// SaveConfig writes cfg atomically to ConfigPath().
func SaveConfig(cfg Config) (string, error) {
	path := ConfigPath()
	err := SaveConfigTo(path, cfg)
	if err != nil && !defender.IsProcessElevated() {
		if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
			fallback := filepath.Join(localApp, "ShieldSheriff", configFileName)
			if fallback != path {
				if fbErr := SaveConfigTo(fallback, cfg); fbErr == nil {
					return fallback, nil
				}
			}
		}
	}
	return path, err
}

// SaveConfigTo atomically writes cfg to path (temp file + fsync + rename) so crashes
// or concurrent readers never observe a truncated config file.
func SaveConfigTo(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	cfg.SchemaVersion = ConfigSchemaVersion
	cfg.Preferences.Normalize()
	if cfg.UpdatedAt.IsZero() {
		cfg.UpdatedAt = time.Now()
	}
	if cfg.Policy.AutoPauseProcesses == nil {
		cfg.Policy.AutoPauseProcesses = []string{}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// isNotExist reports whether err indicates a missing file.
func isNotExist(err error) bool {
	return err != nil && errors.Is(err, os.ErrNotExist)
}
