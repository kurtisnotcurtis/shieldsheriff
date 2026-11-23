package sheriff

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"shieldsheriff/internal/defender"
)

const maxHealBackoff = 5 * time.Minute

// GovernorDeps supplies injectable dependencies for testing without touching the host machine.
type GovernorDeps struct {
	Backend            defender.Backend
	ConfigPath         string
	FindWatchedProcess func([]string) string
	IsStartupEnabled   func() bool
	SetStartup         func(bool) error
	Now                func() time.Time
}

// Governor coordinates Config (Mode, Policy, Preferences, Pause), live Defender Status inspection,
// drift auto-healing, and timed/process-based pause lifecycle.
type Governor struct {
	mu                      sync.RWMutex
	backend                 defender.Backend
	findWatchedProcess      func([]string) string
	isStartupEnabled        func() bool
	setStartup              func(bool) error
	nowFn                   func() time.Time
	config                  Config
	configPath              string
	configModTime           time.Time
	configError             string
	lastStatus              defender.Status
	lastDriftCheck          time.Time
	consecutiveHealFailures int
	nextHealRetryAt         time.Time
	updateInfo              UpdateInfo
	auditLog                []AuditEntry
	onStateSync             func(defender.Status, Config)
	stopCh                  chan struct{}
}

// NewGovernor creates and initializes a Governor backed by the live Windows host.
func NewGovernor() *Governor {
	return NewGovernorWithDeps(GovernorDeps{})
}

// NewGovernorWithDeps creates a Governor using custom dependencies (useful for isolated tests).
func NewGovernorWithDeps(deps GovernorDeps) *Governor {
	if deps.Backend == nil {
		deps.Backend = defender.DefaultBackend()
	}
	if deps.ConfigPath == "" {
		deps.ConfigPath = ConfigPath()
	}
	if deps.FindWatchedProcess == nil {
		deps.FindWatchedProcess = FindRunningWatchedProcess
	}
	if deps.IsStartupEnabled == nil {
		deps.IsStartupEnabled = IsTrayStartupEnabled
	}
	if deps.SetStartup == nil {
		deps.SetStartup = SetTrayStartup
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}

	g := &Governor{
		backend:            deps.Backend,
		findWatchedProcess: deps.FindWatchedProcess,
		isStartupEnabled:   deps.IsStartupEnabled,
		setStartup:         deps.SetStartup,
		nowFn:              deps.Now,
		configPath:         deps.ConfigPath,
		stopCh:             make(chan struct{}),
	}

	cfg, err := LoadConfigFrom(g.configPath)
	switch {
	case err == nil:
		g.config = cfg
		g.recordConfigModTimeLocked()
		g.addAuditLocked("INIT", fmt.Sprintf("Loaded configuration (mode=%s, preset=%s) from %s", cfg.Mode, defender.PresetDisplayName(cfg.Policy.PresetID), g.configPath))
	case isNotExist(err):
		// Genuine first run: inspect live machine state without modifying Defender.
		live := defender.InspectWith(g.backend, nil, nil)
		g.config = Config{
			SchemaVersion: ConfigSchemaVersion,
			UpdatedAt:     g.nowFn(),
			Mode:          defender.ModeUnconfigured,
			Policy: defender.Policy{
				PresetID:              "",
				RealtimeProtection:    live.RealtimeProtection,
				BehaviorMonitoring:    live.BehaviorMonitoring,
				IOAVProtection:        live.IOAVProtection,
				ScriptScanning:        live.ScriptScanning,
				NetworkProtection:     live.NetworkProtection,
				CloudProtection:       live.CloudProtection,
				SampleSubmission:      live.SampleSubmission,
				SuppressAllNags:       live.NagsSuppressed,
				SuppressEnhancedNags:  live.EnhancedNagsSuppressed,
				MuteWindowsSecSystray: live.SecurityTrayIconMuted,
				AutoPauseProcesses:    []string{},
			},
			Preferences: defender.Preferences{
				AutoHeal:            false,
				DriftCheckSeconds:   15,
				StartupEnabled:      g.isStartupEnabled(),
				CheckUpdatesOnStart: false,
			},
		}
		g.addAuditLocked("INIT", "First run detected; awaiting user selection before modifying Defender")
	default:
		// Corrupt or unreadable config: do NOT silently treat as first-run or overwrite.
		g.configError = err.Error()
		g.config = DefaultConfig()
		g.config.Mode = defender.ModePassive
		g.config.Preferences.AutoHeal = false
		g.addAuditLocked("WARN", fmt.Sprintf("Config error (enforcement halted to protect existing file): %v", err))
	}

	g.lastStatus = g.inspectLocked()
	return g
}

func (g *Governor) recordConfigModTimeLocked() {
	if fi, err := os.Stat(g.configPath); err == nil {
		g.configModTime = fi.ModTime()
	}
}

func (g *Governor) reloadIfChangedOnDiskLocked() bool {
	fi, err := os.Stat(g.configPath)
	if err != nil {
		return false
	}
	if !g.configModTime.IsZero() && !fi.ModTime().After(g.configModTime) {
		return false
	}
	cfg, err := LoadConfigFrom(g.configPath)
	if err != nil {
		g.configError = err.Error()
		g.addAuditLocked("WARN", fmt.Sprintf("Skipped reloading modified config (%v)", err))
		g.configModTime = fi.ModTime()
		return false
	}
	g.config = cfg
	g.configError = ""
	g.configModTime = fi.ModTime()
	g.consecutiveHealFailures = 0
	g.nextHealRetryAt = time.Time{}
	g.addAuditLocked("INIT", fmt.Sprintf("Reloaded updated configuration from disk (mode=%s, preset=%s)", cfg.Mode, defender.PresetDisplayName(cfg.Policy.PresetID)))
	return true
}

func (g *Governor) inspectLocked() defender.Status {
	if g.config.Mode == defender.ModeActive {
		p := g.config.Policy
		sd := g.config.Pause
		return defender.InspectWith(g.backend, &p, &sd)
	}
	return defender.InspectWith(g.backend, nil, nil)
}

func (g *Governor) saveLocked() error {
	g.config.UpdatedAt = g.nowFn()
	err := SaveConfigTo(g.configPath, g.config)
	if err == nil {
		g.configError = ""
		g.recordConfigModTimeLocked()
	}
	return err
}

// Mode returns the current governance mode (unconfigured, active, or passive).
func (g *Governor) Mode() defender.Mode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config.Mode
}

// IsUnconfigured reports whether ShieldSheriff has never been configured yet.
func (g *Governor) IsUnconfigured() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config.Mode == defender.ModeUnconfigured
}

// ConfigError returns any config read/parse error encountered on load or reload.
func (g *Governor) ConfigError() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.configError
}

func (g *Governor) addAuditLocked(category, msg string) {
	entry := AuditEntry{
		Timestamp: g.nowFn(),
		Category:  category,
		Message:   msg,
	}
	g.auditLog = append([]AuditEntry{entry}, g.auditLog...)
	if len(g.auditLog) > 100 {
		g.auditLog = g.auditLog[:100]
	}
}

// SetOnStateSync registers a callback invoked whenever state mutates (e.g. to refresh the System Tray icon).
func (g *Governor) SetOnStateSync(fn func(defender.Status, Config)) {
	g.mu.Lock()
	g.onStateSync = fn
	g.mu.Unlock()
}

// Snapshot returns a pure, read-only snapshot of live Defender status, current Config, audit log, and config path.
// It NEVER modifies Defender, never heals drift, and never triggers onStateSync.
func (g *Governor) Snapshot() (defender.Status, Config, []AuditEntry, string) {
	g.mu.RLock()
	cfg := g.config.Clone()
	logs := make([]AuditEntry, len(g.auditLog))
	copy(logs, g.auditLog)
	cfgPath := g.configPath
	backend := g.backend
	g.mu.RUnlock()

	var st defender.Status
	if cfg.Mode == defender.ModeActive {
		p := cfg.Policy
		sd := cfg.Pause
		st = defender.InspectWith(backend, &p, &sd)
	} else {
		st = defender.InspectWith(backend, nil, nil)
	}
	return st, cfg, logs, cfgPath
}

// UpdateConfig validates, saves, and (when mode == ModeActive) enforces the provided Policy and Preferences.
func (g *Governor) UpdateConfig(mode defender.Mode, policy defender.Policy, prefs defender.Preferences) (defender.EnforceResult, error) {
	if !mode.Valid() {
		return defender.EnforceResult{Success: false, Warnings: []string{fmt.Sprintf("invalid mode %q", mode)}}, fmt.Errorf("invalid mode %q", mode)
	}
	if err := policy.Validate(); err != nil {
		return defender.EnforceResult{Success: false, Warnings: []string{err.Error()}}, err
	}
	prefs.Normalize()

	g.mu.Lock()
	prevStartup := g.config.Preferences.StartupEnabled
	g.config.Mode = mode
	g.config.Policy = policy.Clone()
	g.config.Preferences = prefs
	if mode != defender.ModeActive {
		g.config.Pause = defender.PauseState{}
	}
	g.consecutiveHealFailures = 0
	g.nextHealRetryAt = time.Time{}

	saveErr := g.saveLocked()

	var res defender.EnforceResult
	if mode == defender.ModeActive {
		res = defender.EnforceWith(g.backend, g.config.Policy, &g.config.Pause)
	} else {
		res = defender.EnforceResult{Success: true}
	}

	if g.backend.IsElevated() && prefs.StartupEnabled != prevStartup {
		if err := g.setStartup(prefs.StartupEnabled); err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		} else if prefs.StartupEnabled {
			g.addAuditLocked("STARTUP", "Enabled ShieldSheriff tray launch at Windows logon")
		} else {
			g.addAuditLocked("STARTUP", "Disabled ShieldSheriff tray launch at Windows logon")
		}
	}

	g.lastStatus = g.inspectLocked()
	label := defender.PresetDisplayName(policy.PresetID)
	if mode == defender.ModeActive {
		if res.Success {
			g.addAuditLocked("APPLY", fmt.Sprintf("Applied configuration (%s): %d rules applied", label, len(res.Applied)))
		} else if len(res.Warnings) > 0 {
			g.addAuditLocked("WARN", fmt.Sprintf("Saved configuration (%s); enforcement warning: %s", label, res.Warnings[0]))
		}
	}

	cb := g.onStateSync
	st := g.lastStatus
	cfg := g.config.Clone()
	g.mu.Unlock()

	if cb != nil {
		cb(st, cfg)
	}
	return res, saveErr
}

// ApplyPreset switches Defender Policy to the named built-in preset while preserving
// all user app Preferences (StartupEnabled, AutoHeal, DriftCheckSeconds, CheckUpdatesOnStart).
func (g *Governor) ApplyPreset(presetID string) (defender.EnforceResult, error) {
	preset, ok := defender.FindPreset(presetID)
	if !ok {
		err := fmt.Errorf("unknown preset %q (available: %s)", presetID, strings.Join(defender.PresetIDs(), ", "))
		return defender.EnforceResult{Success: false, Warnings: []string{err.Error()}}, err
	}

	g.mu.RLock()
	prefs := g.config.Preferences
	wasUnconfigured := g.config.Mode == defender.ModeUnconfigured
	g.mu.RUnlock()

	if wasUnconfigured {
		// When moving from first-run directly via preset, enable AutoHeal by default.
		prefs.AutoHeal = true
	}
	prefs.Normalize()

	g.mu.Lock()
	g.config.Pause = defender.PauseState{}
	g.mu.Unlock()

	return g.UpdateConfig(defender.ModeActive, preset.Policy, prefs)
}

// EnforceNow forces an immediate enforcement pass if and only if Mode == ModeActive.
func (g *Governor) EnforceNow() defender.EnforceResult {
	g.mu.Lock()
	if g.config.Mode != defender.ModeActive {
		g.mu.Unlock()
		return defender.EnforceResult{
			Success:  false,
			Warnings: []string{"ShieldSheriff is not active (Passive / Unconfigured mode); apply a configuration first"},
		}
	}
	res := defender.EnforceWith(g.backend, g.config.Policy, &g.config.Pause)
	g.lastStatus = g.inspectLocked()
	if res.Success {
		g.addAuditLocked("ENFORCE", fmt.Sprintf("Enforced configuration (%d rules applied)", len(res.Applied)))
	} else if len(res.Warnings) > 0 {
		g.addAuditLocked("WARN", strings.Join(res.Warnings, "; "))
	}
	cb := g.onStateSync
	st := g.lastStatus
	cfg := g.config.Clone()
	g.mu.Unlock()

	if cb != nil {
		cb(st, cfg)
	}
	return res
}

// EnterPassiveMode stops enforcing policies, persists ModePassive, and reverts all ShieldSheriff
// Defender & Security Center registry changes back to their pre-ShieldSheriff snapshot.
func (g *Governor) EnterPassiveMode() (defender.EnforceResult, error) {
	g.mu.Lock()
	g.config.Pause = defender.PauseState{}
	g.config.Mode = defender.ModePassive
	g.consecutiveHealFailures = 0
	g.nextHealRetryAt = time.Time{}

	saveErr := g.saveLocked()
	res := defender.RevertPoliciesWith(g.backend)
	g.lastStatus = g.inspectLocked()

	if res.Success {
		g.addAuditLocked("PASSIVE", "Entered Passive Mode (reverted ShieldSheriff settings to pre-change state)")
	} else if len(res.Warnings) > 0 {
		g.addAuditLocked("WARN", fmt.Sprintf("Passive Mode revert reported issues: %s", res.Warnings[0]))
	}

	cb := g.onStateSync
	st := g.lastStatus
	cfg := g.config.Clone()
	g.mu.Unlock()

	if cb != nil {
		cb(st, cfg)
	}
	return res, saveErr
}

// StartPause pauses Real-Time Protection for the specified duration.
// Refuses to modify Defender when ShieldSheriff is not in ModeActive.
func (g *Governor) StartPause(duration time.Duration, reason string) (defender.EnforceResult, error) {
	if duration <= 0 {
		err := fmt.Errorf("pause duration must be positive")
		return defender.EnforceResult{Success: false, Warnings: []string{err.Error()}}, err
	}

	g.mu.Lock()
	if g.config.Mode != defender.ModeActive {
		g.mu.Unlock()
		msg := "Cannot pause: ShieldSheriff is in Passive / Unconfigured mode (apply a configuration first)"
		return defender.EnforceResult{Success: false, Warnings: []string{msg}}, fmt.Errorf("%s", msg)
	}

	now := g.nowFn()
	g.config.Pause = defender.PauseState{
		Active:    true,
		Reason:    reason,
		StartedAt: now,
		ExpiresAt: now.Add(duration),
	}
	saveErr := g.saveLocked()
	res := defender.EnforceWith(g.backend, g.config.Policy, &g.config.Pause)
	g.lastStatus = g.inspectLocked()
	if res.Success {
		g.addAuditLocked("PAUSE", fmt.Sprintf("Protection paused for %s (%s)", duration.Round(time.Second), reason))
	} else if len(res.Warnings) > 0 {
		g.addAuditLocked("WARN", fmt.Sprintf("Pause requested (%s) with warning: %s", reason, res.Warnings[0]))
	}
	cb := g.onStateSync
	st := g.lastStatus
	cfg := g.config.Clone()
	g.mu.Unlock()

	if cb != nil {
		cb(st, cfg)
	}
	return res, saveErr
}

// ResumePause cancels any active pause and immediately restores the active Policy.
// Refuses to modify Defender when ShieldSheriff is not in ModeActive.
func (g *Governor) ResumePause() (defender.EnforceResult, error) {
	g.mu.Lock()
	if g.config.Mode != defender.ModeActive {
		g.mu.Unlock()
		msg := "Cannot resume: ShieldSheriff is in Passive / Unconfigured mode"
		return defender.EnforceResult{Success: false, Warnings: []string{msg}}, fmt.Errorf("%s", msg)
	}

	g.config.Pause = defender.PauseState{}
	saveErr := g.saveLocked()
	res := defender.EnforceWith(g.backend, g.config.Policy, &g.config.Pause)
	g.lastStatus = g.inspectLocked()
	if res.Success {
		g.addAuditLocked("PAUSE", "Protection resumed")
	} else if len(res.Warnings) > 0 {
		g.addAuditLocked("WARN", fmt.Sprintf("Resume warning: %s", res.Warnings[0]))
	}
	cb := g.onStateSync
	st := g.lastStatus
	cfg := g.config.Clone()
	g.mu.Unlock()

	if cb != nil {
		cb(st, cfg)
	}
	return res, saveErr
}

// StartLoop starts the background drift-watcher and pause timer/process-watch loop.
func (g *Governor) StartLoop() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-g.stopCh:
				return
			case <-ticker.C:
				g.Tick()
			}
		}
	}()
}

// StopLoop stops the background watcher loop.
func (g *Governor) StopLoop() {
	select {
	case <-g.stopCh:
	default:
		close(g.stopCh)
	}
}

// CheckForUpdates queries GitHub for a newer ShieldSheriff release and caches the result.
func (g *Governor) CheckForUpdates() UpdateInfo {
	info := CheckLatestRelease()
	g.mu.Lock()
	g.updateInfo = info
	if info.Error != "" {
		g.addAuditLocked("UPDATE", "Update check failed: "+info.Error)
	} else if info.Available {
		g.addAuditLocked("UPDATE", fmt.Sprintf("Update available: v%s (current v%s)", info.LatestVersion, info.CurrentVersion))
	} else {
		g.addAuditLocked("UPDATE", fmt.Sprintf("Up to date (v%s)", info.CurrentVersion))
	}
	g.mu.Unlock()
	return info
}

// GetUpdateInfo returns the most recent cached update check result.
func (g *Governor) GetUpdateInfo() UpdateInfo {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.updateInfo
}

// Tick runs a single governance cycle: reloads external config changes, enforces active pause
// timers/process watches, and heals drift at the configured interval with failure backoff.
func (g *Governor) Tick() {
	g.mu.Lock()
	now := g.nowFn()
	stateChanged := false

	// 0. Reload config.json if another elevated process (e.g. CLI) updated it.
	if g.reloadIfChangedOnDiskLocked() {
		stateChanged = true
	}

	// Gate ALL enforcement, auto-pause, and drift healing strictly on ModeActive.
	if g.config.Mode != defender.ModeActive {
		g.lastStatus = g.inspectLocked()
		cb := g.onStateSync
		st := g.lastStatus
		cfg := g.config.Clone()
		g.mu.Unlock()
		if stateChanged && cb != nil {
			cb(st, cfg)
		}
		return
	}

	// 1. Check timed Pause expiration
	if g.config.Pause.Active && !g.config.Pause.ExpiresAt.IsZero() && now.After(g.config.Pause.ExpiresAt) {
		g.config.Pause = defender.PauseState{}
		_ = g.saveLocked()
		res := defender.EnforceWith(g.backend, g.config.Policy, &g.config.Pause)
		if res.Success {
			g.addAuditLocked("PAUSE", "Pause timer expired; restored configuration")
		} else if len(res.Warnings) > 0 {
			g.addAuditLocked("WARN", fmt.Sprintf("Pause timer expired, restore warning: %s", res.Warnings[0]))
		}
		stateChanged = true
	}

	// 2. Check AutoPauseProcesses
	if len(g.config.Policy.AutoPauseProcesses) > 0 {
		matched := g.findWatchedProcess(g.config.Policy.AutoPauseProcesses)
		if matched != "" && !g.config.Pause.Active {
			g.config.Pause = defender.PauseState{
				Active:         true,
				Reason:         "Watched process running: " + matched,
				StartedAt:      now,
				MatchedProcess: matched,
			}
			_ = g.saveLocked()
			res := defender.EnforceWith(g.backend, g.config.Policy, &g.config.Pause)
			if res.Success {
				g.addAuditLocked("PAUSE", fmt.Sprintf("Auto-pause triggered by %s", matched))
			} else if len(res.Warnings) > 0 {
				g.addAuditLocked("WARN", fmt.Sprintf("Auto-pause (%s) warning: %s", matched, res.Warnings[0]))
			}
			stateChanged = true
		} else if matched == "" && g.config.Pause.Active && g.config.Pause.MatchedProcess != "" && g.config.Pause.ExpiresAt.IsZero() {
			prevProc := g.config.Pause.MatchedProcess
			g.config.Pause = defender.PauseState{}
			_ = g.saveLocked()
			res := defender.EnforceWith(g.backend, g.config.Policy, &g.config.Pause)
			if res.Success {
				g.addAuditLocked("PAUSE", fmt.Sprintf("Watched process %s exited; restored Real-Time Protection", prevProc))
			} else if len(res.Warnings) > 0 {
				g.addAuditLocked("WARN", fmt.Sprintf("Restore after %s warning: %s", prevProc, res.Warnings[0]))
			}
			stateChanged = true
		}
	}

	// 3. Inspect live state & heal drift at configured interval with failure backoff.
	driftInterval := time.Duration(g.config.Preferences.DriftCheckSeconds) * time.Second
	if driftInterval < 10*time.Second {
		driftInterval = 15 * time.Second
	}
	st := g.lastStatus
	prevCompliance := st.InCompliance
	if g.lastDriftCheck.IsZero() || now.Sub(g.lastDriftCheck) >= driftInterval {
		g.lastDriftCheck = now
		st = g.inspectLocked()
		if st.InCompliance {
			g.consecutiveHealFailures = 0
			g.nextHealRetryAt = time.Time{}
		} else if g.config.Preferences.AutoHeal && st.IsElevated && !st.TamperProtectionActive {
			if g.nextHealRetryAt.IsZero() || !now.Before(g.nextHealRetryAt) {
				driftSummary := strings.Join(st.DriftItems, ", ")
				res := defender.EnforceWith(g.backend, g.config.Policy, &g.config.Pause)
				post := g.inspectLocked()
				if res.Success && post.InCompliance {
					g.consecutiveHealFailures = 0
					g.nextHealRetryAt = time.Time{}
					g.addAuditLocked("DRIFT", fmt.Sprintf("Auto-healed configuration drift (%s)", driftSummary))
					st = post
					stateChanged = true
				} else {
					g.consecutiveHealFailures++
					backoff := 30 * time.Second << min(g.consecutiveHealFailures-1, 4)
					if backoff > maxHealBackoff {
						backoff = maxHealBackoff
					}
					g.nextHealRetryAt = now.Add(backoff)
					reason := "drift persisted after enforce"
					if len(res.Warnings) > 0 {
						reason = res.Warnings[0]
					}
					g.addAuditLocked("WARN", fmt.Sprintf("Auto-heal failed (%s); backing off for %s", reason, backoff))
					st = post
				}
			}
		}
		g.lastStatus = st
	}

	cb := g.onStateSync
	cfg := g.config.Clone()
	g.mu.Unlock()

	if (stateChanged || prevCompliance != st.InCompliance) && cb != nil {
		cb(st, cfg)
	}
}
