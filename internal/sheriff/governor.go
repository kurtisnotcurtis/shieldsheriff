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
	mu          sync.RWMutex
	orders      defender.StandingOrders
	configPath  string
	standDown   defender.StandDownState
	lastStatus  defender.DeputyStatus
	auditLog    []AuditEntry
	onStateSync func(defender.DeputyStatus, defender.StandingOrders, defender.StandDownState)
	stopCh      chan struct{}
}

// NewGovernor creates and initializes a Governor instance.
func NewGovernor() *Governor {
	orders, path, err := LoadOrders()
	g := &Governor{
		orders:     orders,
		configPath: path,
		stopCh:     make(chan struct{}),
	}
	if err != nil {
		g.addAuditLocked("INIT", "Initialized default Quiet Guardian standing orders")
	} else {
		g.addAuditLocked("INIT", fmt.Sprintf("Loaded Standing Orders (%s) from %s", orders.PresetName, path))
	}
	g.lastStatus = defender.Inspect(&g.orders, &g.standDown)
	return g
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
	defer g.mu.Unlock()
	g.lastStatus = defender.Inspect(&g.orders, &g.standDown)
	logs := make([]AuditEntry, len(g.auditLog))
	copy(logs, g.auditLog)
	return g.lastStatus, g.orders, g.standDown, logs, g.configPath
}

// UpdateOrders saves and enforces new StandingOrders.
func (g *Governor) UpdateOrders(orders defender.StandingOrders) (defender.EnforceResult, error) {
	g.mu.Lock()
	g.orders = orders
	path, saveErr := SaveOrders(g.orders)
	g.configPath = path
	res := defender.Enforce(g.orders, &g.standDown)
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

	// 2. Check AutoStandDownProcesses (disabled in early build)
	if false && len(g.orders.AutoStandDownProcesses) > 0 {
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

	// 3. Inspect live state & heal drift if Elected + EnforceLoop + Elevated
	st := defender.Inspect(&g.orders, &g.standDown)
	if g.orders.Elected && g.orders.EnforceLoop && !st.InCompliance && st.IsElevated && !st.TamperProtectionActive {
		res := defender.Enforce(g.orders, &g.standDown)
		if res.Success {
			g.addAuditLocked("DRIFT", fmt.Sprintf("Auto-healed configuration drift (%s)", strings.Join(st.DriftItems, ", ")))
			st = defender.Inspect(&g.orders, &g.standDown)
			stateChanged = true
		}
	}

	prevCompliance := g.lastStatus.InCompliance
	g.lastStatus = st
	cb := g.onStateSync
	ord := g.orders
	sd := g.standDown
	g.mu.Unlock()

	if (stateChanged || prevCompliance != st.InCompliance) && cb != nil {
		cb(st, ord, sd)
	}
}
