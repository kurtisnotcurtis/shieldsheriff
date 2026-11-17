package sheriff

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"shieldsheriff/internal/defender"
)

var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modKernel32.NewProc("Process32NextW")
)

const (
	th32csSnapProcess = 0x00000002
	maxPath           = 260
)

type processEntry32W struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [maxPath]uint16
}

// FindRunningWatchedProcess checks running processes via Win32 Toolhelp32 snapshot
// and returns the first process name from watchList that is currently running.
func FindRunningWatchedProcess(watchList []string) string {
	if len(watchList) == 0 {
		return ""
	}
	watchSet := make(map[string]string, len(watchList))
	for _, w := range watchList {
		clean := strings.TrimSpace(strings.ToLower(w))
		if clean != "" {
			if !strings.HasSuffix(clean, ".exe") {
				clean += ".exe"
			}
			watchSet[clean] = w
		}
	}
	if len(watchSet) == 0 {
		return ""
	}

	snap, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == ^uintptr(0) {
		return ""
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))
	r1, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if r1 == 0 {
		return ""
	}
	for {
		exeName := strings.ToLower(syscall.UTF16ToString(entry.ExeFile[:]))
		if orig, ok := watchSet[exeName]; ok {
			return orig
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		r1, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if r1 == 0 {
			break
		}
	}
	return ""
}

// Governor coordinates StandingOrders, live DeputyStatus inspection, drift auto-healing,
// and temporary Stand-Down timers/process watches.
type Governor struct {
	mu             sync.RWMutex
	orders         defender.StandingOrders
	configPath     string
	firstRun       bool
	standDown      defender.StandDownState
	lastStatus     defender.DeputyStatus
	lastDriftCheck time.Time
	updateInfo     UpdateInfo
	auditLog       []AuditEntry
	onStateSync    func(defender.DeputyStatus, defender.StandingOrders, defender.StandDownState)
	stopCh         chan struct{}
}

// NewGovernor creates and initializes a Governor instance.
func NewGovernor() *Governor {
	orders, path, err := LoadOrders()
	firstRun := false
	if err != nil {
		firstRun = true
		orders.Elected = false
	}
	if orders.DriftCheckSeconds <= 0 {
		orders.DriftCheckSeconds = 15
	}
	g := &Governor{
		orders:     orders,
		configPath: path,
		firstRun:   firstRun,
		stopCh:     make(chan struct{}),
	}
	if firstRun {
		g.addAuditLocked("INIT", "First run detected; awaiting user selection before modifying Defender")
	} else {
		g.addAuditLocked("INIT", fmt.Sprintf("Loaded Standing Orders (%s) from %s", orders.PresetName, path))
	}
	g.lastStatus = defender.Inspect(&g.orders, &g.standDown)
	if firstRun {
		g.orders = defender.StandingOrders{
			UpdatedAt:             time.Now(),
			PresetName:            "unconfigured",
			Elected:               false,
			EnforceLoop:           false,
			DriftCheckSeconds:     15,
			StartupEnabled:        IsTrayStartupEnabled(),
			CheckUpdatesOnStart:   false,
			RealtimeProtection:    g.lastStatus.RealtimeProtection,
			BehaviorMonitoring:    g.lastStatus.BehaviorMonitoring,
			IOAVProtection:        g.lastStatus.IOAVProtection,
			ScriptScanning:        g.lastStatus.ScriptScanning,
			NetworkProtection:     g.lastStatus.NetworkProtection,
			CloudProtection:       g.lastStatus.CloudProtection,
			SampleSubmission:      g.lastStatus.SampleSubmission,
			SuppressAllNags:       g.lastStatus.NagsSuppressed,
			SuppressEnhancedNags:  g.lastStatus.EnhancedNagsSuppressed,
			MuteWindowsSecSystray: g.lastStatus.SecurityTrayIconMuted,
		}
		g.lastStatus = defender.Inspect(&g.orders, &g.standDown)
	}
	return g
}

// IsFirstRun reports whether ShieldSheriff is awaiting initial user setup/consent.
func (g *Governor) IsFirstRun() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.firstRun || !g.orders.Elected
}

func (g *Governor) addAuditLocked(category, msg string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Category:  category,
		Message:   msg,
	}
	g.auditLog = append([]AuditEntry{entry}, g.auditLog...)
	if len(g.auditLog) > 100 {
		g.auditLog = g.auditLog[:100]
	}
}

// SetOnStateSync registers a callback invoked whenever state changes (e.g., to update the System Tray icon).
func (g *Governor) SetOnStateSync(fn func(defender.DeputyStatus, defender.StandingOrders, defender.StandDownState)) {
	g.mu.Lock()
	g.onStateSync = fn
	g.mu.Unlock()
}

// Snapshot returns a thread-safe copy of the current status, orders, stand-down state, and audit log.
func (g *Governor) Snapshot() (defender.DeputyStatus, defender.StandingOrders, defender.StandDownState, []AuditEntry, string) {
	g.mu.Lock()
	st := defender.Inspect(&g.orders, &g.standDown)
	st, healed := g.healDriftLocked(st)
	g.lastStatus = st
	logs := make([]AuditEntry, len(g.auditLog))
	copy(logs, g.auditLog)
	ord := g.orders
	sd := g.standDown
	cfg := g.configPath
	cb := g.onStateSync
	g.mu.Unlock()

	if healed && cb != nil {
		cb(st, ord, sd)
	}
	return st, ord, sd, logs, cfg
}

func (g *Governor) healDriftLocked(st defender.DeputyStatus) (defender.DeputyStatus, bool) {
	if g.orders.Elected && g.orders.EnforceLoop && !st.InCompliance && st.IsElevated && !st.TamperProtectionActive {
		res := defender.Enforce(g.orders, &g.standDown)
		if res.Success {
			g.addAuditLocked("DRIFT", fmt.Sprintf("Auto-healed configuration drift (%s)", strings.Join(st.DriftItems, ", ")))
			return defender.Inspect(&g.orders, &g.standDown), true
		}
	}
	return st, false
}

// UpdateOrders saves and enforces new StandingOrders.
func (g *Governor) UpdateOrders(orders defender.StandingOrders) (defender.EnforceResult, error) {
	g.mu.Lock()
	if orders.DriftCheckSeconds <= 0 {
		orders.DriftCheckSeconds = 15
	}
	prevStartup := g.orders.StartupEnabled
	orders.Elected = true
	g.firstRun = false
	g.orders = orders
	path, saveErr := SaveOrders(g.orders)
	g.configPath = path
	res := defender.Enforce(g.orders, &g.standDown)
	if defender.IsProcessElevated() && orders.StartupEnabled != prevStartup {
		if err := SetTrayStartup(orders.StartupEnabled); err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		} else if orders.StartupEnabled {
			g.addAuditLocked("STARTUP", "Enabled ShieldSheriff tray launch at Windows logon")
		} else {
			g.addAuditLocked("STARTUP", "Disabled ShieldSheriff tray launch at Windows logon")
		}
	}
	g.lastStatus = defender.Inspect(&g.orders, &g.standDown)
	if res.Success {
		g.addAuditLocked("ENFORCE", fmt.Sprintf("Applied Standing Orders (%s): %d policies enforced", orders.PresetName, len(res.Applied)))
	} else if len(res.Warnings) > 0 {
		g.addAuditLocked("WARN", fmt.Sprintf("Saved Standing Orders (%s); enforcement pending elevation: %s", orders.PresetName, res.Warnings[0]))
	}
	cb := g.onStateSync
	st := g.lastStatus
	sd := g.standDown
	g.mu.Unlock()

	if cb != nil {
		cb(st, orders, sd)
	}
	return res, saveErr
}

// EnforceNow forces an immediate enforcement pass of the current StandingOrders.
func (g *Governor) EnforceNow() defender.EnforceResult {
	g.mu.Lock()
	res := defender.Enforce(g.orders, &g.standDown)
	g.lastStatus = defender.Inspect(&g.orders, &g.standDown)
	if res.Success {
		g.addAuditLocked("ENFORCE", fmt.Sprintf("Enforced Standing Orders (%d rules applied)", len(res.Applied)))
	} else if len(res.Warnings) > 0 {
		g.addAuditLocked("WARN", strings.Join(res.Warnings, "; "))
	}
	cb := g.onStateSync
	st := g.lastStatus
	ord := g.orders
	sd := g.standDown
	g.mu.Unlock()

	if cb != nil {
		cb(st, ord, sd)
	}
	return res
}

// EnterPassiveMode stops enforcing policies and reverts ShieldSheriff's policy overrides.
func (g *Governor) EnterPassiveMode() defender.EnforceResult {
	g.mu.Lock()
	g.standDown = defender.StandDownState{}
	g.orders.Elected = false
	g.orders.PresetName = "passive"
	_, _ = SaveOrders(g.orders)
	res := defender.RevertPolicies()
	g.lastStatus = defender.Inspect(&g.orders, &g.standDown)
	g.addAuditLocked("PASSIVE", "Entered Passive Mode (reverted policy overrides; passthrough)")
	cb := g.onStateSync
	st := g.lastStatus
	ord := g.orders
	sd := g.standDown
	g.mu.Unlock()

	if cb != nil {
		cb(st, ord, sd)
	}
	return res
}

// StartStandDown pauses Real-Time Protection for the specified duration.
func (g *Governor) StartStandDown(duration time.Duration, reason string) defender.EnforceResult {
	g.mu.Lock()
	now := time.Now()
	g.standDown = defender.StandDownState{
		Active:    true,
		Reason:    reason,
		StartedAt: now,
		ExpiresAt: now.Add(duration),
	}
	res := defender.Enforce(g.orders, &g.standDown)
	g.lastStatus = defender.Inspect(&g.orders, &g.standDown)
	g.addAuditLocked("STANDDOWN", fmt.Sprintf("Deputy ordered to stand down for %s (%s)", duration.Round(time.Second), reason))
	cb := g.onStateSync
	st := g.lastStatus
	ord := g.orders
	sd := g.standDown
	g.mu.Unlock()

	if cb != nil {
		cb(st, ord, sd)
	}
	return res
}

// ResumeFromStandDown cancels any active Stand-Down and immediately restores StandingOrders.
func (g *Governor) ResumeFromStandDown() defender.EnforceResult {
	g.mu.Lock()
	g.standDown = defender.StandDownState{}
	res := defender.Enforce(g.orders, &g.standDown)
	g.lastStatus = defender.Inspect(&g.orders, &g.standDown)
	g.addAuditLocked("STANDDOWN", "Deputy resumed normal duty under Standing Orders")
	cb := g.onStateSync
	st := g.lastStatus
	ord := g.orders
	sd := g.standDown
	g.mu.Unlock()

	if cb != nil {
		cb(st, ord, sd)
	}
	return res
}

// StartLoop starts the background drift-watcher and process/timer Stand-Down loop.
func (g *Governor) StartLoop() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-g.stopCh:
				return
			case <-ticker.C:
				g.tick()
			}
		}
	}()
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
// StopLoop stops the background watcher loop.
func (g *Governor) StopLoop() {
	select {
	case <-g.stopCh:
	default:
		close(g.stopCh)
	}
}

func (g *Governor) tick() {
	g.mu.Lock()
	now := time.Now()
	stateChanged := false

	// 1. Check timed Stand-Down expiration
	if g.standDown.Active && !g.standDown.ExpiresAt.IsZero() && now.After(g.standDown.ExpiresAt) {
		g.standDown = defender.StandDownState{}
		_ = defender.Enforce(g.orders, &g.standDown)
		g.addAuditLocked("STANDDOWN", "Stand-Down timer expired; restored Standing Orders")
		stateChanged = true
	}

	// 2. Check AutoStandDownProcesses
	if len(g.orders.AutoStandDownProcesses) > 0 {
		matched := FindRunningWatchedProcess(g.orders.AutoStandDownProcesses)
		if matched != "" && !g.standDown.Active {
			g.standDown = defender.StandDownState{
				Active:         true,
				Reason:         "Watched process running: " + matched,
				StartedAt:      now,
				MatchedProcess: matched,
			}
			_ = defender.Enforce(g.orders, &g.standDown)
			g.addAuditLocked("STANDDOWN", fmt.Sprintf("Auto Stand-Down triggered by %s", matched))
			stateChanged = true
		} else if matched == "" && g.standDown.Active && g.standDown.MatchedProcess != "" && g.standDown.ExpiresAt.IsZero() {
			prevProc := g.standDown.MatchedProcess
			g.standDown = defender.StandDownState{}
			_ = defender.Enforce(g.orders, &g.standDown)
			g.addAuditLocked("STANDDOWN", fmt.Sprintf("Watched process %s exited; restored Real-Time Protection", prevProc))
			stateChanged = true
		}
	}

	// 3. Inspect live state & heal drift at configured interval if Elected + EnforceLoop + Elevated
	driftInterval := time.Duration(g.orders.DriftCheckSeconds) * time.Second
	if driftInterval < 10*time.Second {
		driftInterval = 15 * time.Second
	}
	st := g.lastStatus
	prevCompliance := st.InCompliance
	if now.Sub(g.lastDriftCheck) >= driftInterval {
		g.lastDriftCheck = now
		st = defender.Inspect(&g.orders, &g.standDown)
		var healed bool
		st, healed = g.healDriftLocked(st)
		if healed {
			stateChanged = true
		}
		g.lastStatus = st
	}

	cb := g.onStateSync
	ord := g.orders
	sd := g.standDown
	g.mu.Unlock()

	if (stateChanged || prevCompliance != st.InCompliance) && cb != nil {
		cb(st, ord, sd)
	}
}
