package sheriff

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"shieldsheriff/internal/defender"
)

type testRegVal struct {
	kind   defender.RegValueKind
	dword  uint32
	strVal string
}

type fakeDefenderBackend struct {
	mu           sync.Mutex
	elevated     bool
	vals         map[string]testRegVal
	writeCount   int
	failAllWrite error
}

func newFakeDefenderBackend(elevated bool) *fakeDefenderBackend {
	return &fakeDefenderBackend{
		elevated: elevated,
		vals:     make(map[string]testRegVal),
	}
}

func (f *fakeDefenderBackend) key(root defender.RegRoot, subkey, name string) string {
	r := "HKLM"
	if root == defender.HKCU {
		r = "HKCU"
	}
	return r + `\` + subkey + `\` + name
}

func (f *fakeDefenderBackend) IsElevated() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.elevated
}

func (f *fakeDefenderBackend) ReadDword(root defender.RegRoot, subkey, name string) (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vals[f.key(root, subkey, name)]
	if !ok || v.kind != defender.RegDword {
		return 0, false
	}
	return v.dword, true
}

func (f *fakeDefenderBackend) ReadString(root defender.RegRoot, subkey, name string) (string, defender.RegValueKind, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vals[f.key(root, subkey, name)]
	if !ok || (v.kind != defender.RegSZ && v.kind != defender.RegExpandSZ) {
		return "", 0, false
	}
	return v.strVal, v.kind, true
}

func (f *fakeDefenderBackend) WriteDword(root defender.RegRoot, subkey, name string, val uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeCount++
	if f.failAllWrite != nil {
		return f.failAllWrite
	}
	f.vals[f.key(root, subkey, name)] = testRegVal{kind: defender.RegDword, dword: val}
	return nil
}

func (f *fakeDefenderBackend) WriteString(root defender.RegRoot, subkey, name string, val string, kind defender.RegValueKind) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeCount++
	if f.failAllWrite != nil {
		return f.failAllWrite
	}
	f.vals[f.key(root, subkey, name)] = testRegVal{kind: kind, strVal: val}
	return nil
}

func (f *fakeDefenderBackend) DeleteValue(root defender.RegRoot, subkey, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.vals, f.key(root, subkey, name))
	return nil
}

func (f *fakeDefenderBackend) RunCommand(ctx context.Context, name string, args ...string) (string, error) {
	return "ok", nil
}

func (f *fakeDefenderBackend) FileExists(path string) bool { return false }

func TestFindRunningWatchedProcess(t *testing.T) {
	if m := FindRunningWatchedProcess([]string{"definitely_not_running_xyz999.exe"}); m != "" {
		t.Fatalf("expected empty match, got %q", m)
	}
	selfExe := filepath.Base(os.Args[0])
	if m := FindRunningWatchedProcess([]string{selfExe}); m == "" {
		t.Fatalf("expected current test binary %q to be detected via Toolhelp32 snapshot", selfExe)
	}
}

func TestGovernorModeGatePreventsUnconfiguredOrPassiveEnforcement(t *testing.T) {
	b := newFakeDefenderBackend(true)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	watched := "cargo.exe"

	gov := NewGovernorWithDeps(GovernorDeps{
		Backend:            b,
		ConfigPath:         cfgPath,
		FindWatchedProcess: func([]string) string { return watched },
		IsStartupEnabled:   func() bool { return false },
		SetStartup:         func(bool) error { return nil },
	})

	if gov.Mode() != defender.ModeUnconfigured {
		t.Fatalf("expected ModeUnconfigured on fresh config path, got %s", gov.Mode())
	}

	// EnforceNow, StartPause, ResumePause, and Tick must all refuse to mutate Defender in ModeUnconfigured.
	if res := gov.EnforceNow(); res.Success {
		t.Fatal("expected EnforceNow to refuse in ModeUnconfigured")
	}
	if _, err := gov.StartPause(10*time.Minute, "test"); err == nil {
		t.Fatal("expected StartPause to fail in ModeUnconfigured")
	}
	if _, err := gov.ResumePause(); err == nil {
		t.Fatal("expected ResumePause to fail in ModeUnconfigured")
	}
	gov.Tick()
	if b.writeCount != 0 {
		t.Fatalf("expected 0 registry writes while unconfigured, got %d", b.writeCount)
	}

	// Activate workstation preset (has AutoPauseProcesses), then enter Passive Mode.
	if _, err := gov.ApplyPreset("workstation"); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	if _, err := gov.EnterPassiveMode(); err != nil {
		t.Fatalf("EnterPassiveMode failed: %v", err)
	}
	writesAfterPassive := b.writeCount
	// Even with cargo.exe running, Tick must NOT enforce policies in Passive Mode!
	gov.Tick()
	if b.writeCount != writesAfterPassive {
		t.Fatalf("expected Tick in Passive Mode to perform 0 writes, got %d new writes", b.writeCount-writesAfterPassive)
	}
}

func TestGovernorSnapshotIsPureAndNeverHeals(t *testing.T) {
	b := newFakeDefenderBackend(true)
	cfgPath := filepath.Join(t.TempDir(), "config.json")

	gov := NewGovernorWithDeps(GovernorDeps{
		Backend:          b,
		ConfigPath:       cfgPath,
		IsStartupEnabled: func() bool { return false },
		SetStartup:       func(bool) error { return nil },
	})

	if _, err := gov.ApplyPreset("local-protection"); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	// Simulate drift: Windows Update flips Cloud Protection back on
	_ = b.WriteDword(defender.HKLM, `SOFTWARE\Microsoft\Windows Defender\Spynet`, "SpyNetReporting", 2)

	writesBefore := b.writeCount
	syncCalled := false
	gov.SetOnStateSync(func(defender.Status, Config) { syncCalled = true })

	st, _, _, _ := gov.Snapshot()
	if st.InCompliance {
		t.Fatal("expected Snapshot to report drift")
	}
	if b.writeCount != writesBefore {
		t.Fatalf("expected Snapshot to be pure (0 writes), got %d writes", b.writeCount-writesBefore)
	}
	if syncCalled {
		t.Fatal("expected Snapshot to never fire onStateSync callback")
	}
}

func TestGovernorApplyPresetPreservesPreferences(t *testing.T) {
	b := newFakeDefenderBackend(true)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	startupCalls := []bool{}

	gov := NewGovernorWithDeps(GovernorDeps{
		Backend:          b,
		ConfigPath:       cfgPath,
		IsStartupEnabled: func() bool { return false },
		SetStartup: func(enabled bool) error {
			startupCalls = append(startupCalls, enabled)
			return nil
		},
	})

	prefs := defender.Preferences{
		AutoHeal:            true,
		DriftCheckSeconds:   60,
		StartupEnabled:      true,
		CheckUpdatesOnStart: true,
	}
	if _, err := gov.UpdateConfig(defender.ModeActive, defender.DefaultPolicy(), prefs); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}
	if len(startupCalls) != 1 || !startupCalls[0] {
		t.Fatalf("expected startup enabled once, got %v", startupCalls)
	}

	// Switch presets: StartupEnabled, DriftCheckSeconds, and CheckUpdatesOnStart MUST be preserved!
	if _, err := gov.ApplyPreset("workstation"); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	_, cfg, _, _ := gov.Snapshot()
	if !cfg.Preferences.StartupEnabled || cfg.Preferences.DriftCheckSeconds != 60 || !cfg.Preferences.CheckUpdatesOnStart {
		t.Fatalf("ApplyPreset overwrote user preferences: %+v", cfg.Preferences)
	}
	if len(startupCalls) != 1 {
		t.Fatalf("ApplyPreset should not toggle logon task; startupCalls=%v", startupCalls)
	}
}

func TestGovernorTickLifecycleAndHealBackoff(t *testing.T) {
	b := newFakeDefenderBackend(true)
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	runningProc := ""

	gov := NewGovernorWithDeps(GovernorDeps{
		Backend:            b,
		ConfigPath:         cfgPath,
		FindWatchedProcess: func([]string) string { return runningProc },
		IsStartupEnabled:   func() bool { return false },
		SetStartup:         func(bool) error { return nil },
		Now:                func() time.Time { return now },
	})

	if _, err := gov.ApplyPreset("workstation"); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}

	// 1. Timed pause starts and persists in config.json, then expires cleanly on Tick
	if _, err := gov.StartPause(10*time.Minute, "Unit Test Pause"); err != nil {
		t.Fatalf("StartPause failed: %v", err)
	}
	reloaded, err := LoadConfigFrom(cfgPath)
	if err != nil || !reloaded.Pause.Active {
		t.Fatalf("expected persisted pause in config.json, got %+v err=%v", reloaded.Pause, err)
	}

	now = now.Add(11 * time.Minute)
	gov.Tick()
	_, cfg, _, _ := gov.Snapshot()
	if cfg.Pause.Active {
		t.Fatal("expected pause timer to expire after Tick")
	}

	// 2. Watched process auto-pause triggers and clears
	runningProc = "cargo.exe"
	now = now.Add(5 * time.Second)
	gov.Tick()
	_, cfg, _, _ = gov.Snapshot()
	if !cfg.Pause.Active || cfg.Pause.MatchedProcess != "cargo.exe" {
		t.Fatalf("expected auto-pause for cargo.exe, got %+v", cfg.Pause)
	}

	runningProc = ""
	now = now.Add(5 * time.Second)
	gov.Tick()
	_, cfg, _, _ = gov.Snapshot()
	if cfg.Pause.Active {
		t.Fatal("expected auto-pause to clear when cargo.exe exits")
	}

	// 3. Drift healing heals cleanly, and persistent write failure triggers backoff
	_ = b.WriteDword(defender.HKLM, `SOFTWARE\Microsoft\Windows Defender\Spynet`, "SpyNetReporting", 2)
	b.failAllWrite = errors.New("simulated access denied")
	writesBeforeFail := b.writeCount

	now = now.Add(30 * time.Second)
	gov.Tick()
	writesAfterFirstFail := b.writeCount
	if writesAfterFirstFail <= writesBeforeFail {
		t.Fatal("expected first heal attempt to run")
	}

	// Advance 15s (past DriftCheckSeconds, but still inside 30s backoff window) -> must NOT retry!
	now = now.Add(15 * time.Second)
	gov.Tick()
	if b.writeCount != writesAfterFirstFail {
		t.Fatalf("expected backoff to suppress retry; writes went from %d to %d", writesAfterFirstFail, b.writeCount)
	}
}

func TestConfigMigrationAndCorruptHandling(t *testing.T) {
	dir := t.TempDir()

	// 1. Legacy v1 config migrates seamlessly
	v1Path := filepath.Join(dir, "v1.json")
	v1JSON := `{
		"presetName": "workstation",
		"elected": true,
		"enforceLoop": true,
		"driftCheckSeconds": 30,
		"startupEnabled": true,
		"realtimeProtection": true,
		"behaviorMonitoring": false,
		"ioavProtection": true,
		"scriptScanning": false,
		"cloudProtection": 0,
		"sampleSubmission": 2,
		"suppressAllNags": true,
		"autoStandDownProcesses": ["cargo.exe"]
	}`
	if err := os.WriteFile(v1Path, []byte(v1JSON), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFrom(v1Path)
	if err != nil {
		t.Fatalf("expected legacy v1 migration to succeed, got %v", err)
	}
	if cfg.Mode != defender.ModeActive || cfg.Policy.PresetID != "workstation" || !cfg.Preferences.StartupEnabled || len(cfg.Policy.AutoPauseProcesses) != 1 {
		t.Fatalf("unexpected migrated config: %+v", cfg)
	}

	// 2. Corrupt config does NOT silently masquerade as first-run
	badPath := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(badPath, []byte(`{"schemaVersion": 2, truncated`), 0644); err != nil {
		t.Fatal(err)
	}
	gov := NewGovernorWithDeps(GovernorDeps{
		Backend:          newFakeDefenderBackend(true),
		ConfigPath:       badPath,
		IsStartupEnabled: func() bool { return false },
		SetStartup:       func(bool) error { return nil },
	})
	if gov.ConfigError() == "" {
		t.Fatal("expected ConfigError to be populated for corrupt config.json")
	}
	if gov.Mode() == defender.ModeActive || gov.IsUnconfigured() {
		t.Fatalf("corrupt config should halt in passive mode rather than active/first-run, got %s", gov.Mode())
	}
}
