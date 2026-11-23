//go:build windows

package tray

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"shieldsheriff/internal/defender"
	"shieldsheriff/internal/sheriff"
)

var (
	modShell32             = syscall.NewLazyDLL("shell32.dll")
	modKernel32            = syscall.NewLazyDLL("kernel32.dll")
	procShellNotifyIconW   = modShell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW   = modKernel32.NewProc("GetModuleHandleW")
	procRegisterClassExW   = modUser32.NewProc("RegisterClassExW")
	procRegisterWindowMsgW = modUser32.NewProc("RegisterWindowMessageW")
	procCreateWindowExW    = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW     = modUser32.NewProc("DefWindowProcW")
	procGetMessageW        = modUser32.NewProc("GetMessageW")
	procTranslateMessage   = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW   = modUser32.NewProc("DispatchMessageW")
	procPostQuitMessage    = modUser32.NewProc("PostQuitMessage")
	procPostMessageW       = modUser32.NewProc("PostMessageW")
	procDestroyWindow      = modUser32.NewProc("DestroyWindow")
	procCreatePopupMenu    = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW        = modUser32.NewProc("AppendMenuW")
	procDestroyMenu        = modUser32.NewProc("DestroyMenu")
	procTrackPopupMenu     = modUser32.NewProc("TrackPopupMenu")
	procSetForegroundWin   = modUser32.NewProc("SetForegroundWindow")
	procGetCursorPos       = modUser32.NewProc("GetCursorPos")
)

const (
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
	wmUser            = 0x0400
	wmTrayCallback    = wmUser + 1
	wmSyncTrayState   = wmUser + 2
	wmShowBalloon     = wmUser + 3

	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205
	wmContextMenu   = 0x007B

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010

	mfString    = 0x00000000
	mfChecked   = 0x00000008
	mfPopup     = 0x00000010
	mfSeparator = 0x00000800

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
)

// Menu command IDs
const (
	cmdOpenDashboard = 1001
	cmdElevateNow    = 1002

	cmdPresetBase = 1010 // 1010 + index in defender.BuiltinPresets()

	cmdPause15m    = 1040
	cmdPause30m    = 1041
	cmdPause1h     = 1042
	cmdPause4h     = 1043
	cmdPauseResume = 1044
	cmdPassiveMode = 1045

	cmdActionQuickScan  = 1050
	cmdActionSigUpdate  = 1051
	cmdActionOpenWinSec = 1052

	cmdExit = 1099
)

type wndClassExW struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type point struct {
	X int32
	Y int32
}

type msg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type notifyIconDataW struct {
	CbSize           uint32
	Hwnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         guid
	HBalloonIcon     uintptr
}

type balloonMsg struct {
	title string
	body  string
}

// AppTray manages the native Win32 System Tray icon and context menu for ShieldSheriff.
// All Shell_NotifyIconW calls are marshaled onto the tray UI thread so notifyIconDataW
// is never mutated concurrently.
type AppTray struct {
	gov               *sheriff.Governor
	openDashboard     func()
	hwnd              uintptr // accessed atomically across goroutines
	taskbarCreatedMsg uint32
	presets           []defender.Preset

	iconPassive  uintptr
	iconPause    uintptr
	iconOnDemand uintptr
	iconDev      uintptr
	iconQuiet    uintptr
	iconFull     uintptr
	iconCustom   uintptr

	nid notifyIconDataW // UI thread only

	balloonMu       sync.Mutex
	pendingBalloons []balloonMsg
}

var activeTray *AppTray

// NewAppTray constructs the System Tray controller.
func NewAppTray(gov *sheriff.Governor, openDashboard func()) *AppTray {
	t := &AppTray{
		gov:           gov,
		openDashboard: openDashboard,
		presets:       defender.BuiltinPresets(),
	}
	gov.SetOnStateSync(func(_ defender.Status, _ sheriff.Config) {
		if h := atomic.LoadUintptr(&t.hwnd); h != 0 {
			procPostMessageW.Call(h, wmSyncTrayState, 0, 0)
		}
	})
	return t
}

// Quit requests the system tray message loop to exit cleanly.
func (t *AppTray) Quit() {
	if h := atomic.LoadUintptr(&t.hwnd); h != 0 {
		procPostMessageW.Call(h, wmClose, 0, 0)
	}
}

// Run starts the Win32 System Tray message loop on the current goroutine.
func (t *AppTray) Run() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	activeTray = t
	t.iconPassive = CreateSheriffBadgeIcon(BadgePassive)
	t.iconPause = CreateSheriffBadgeIcon(BadgePause)
	t.iconOnDemand = CreateSheriffBadgeIcon(BadgePresetOnDemand)
	t.iconDev = CreateSheriffBadgeIcon(BadgePresetDev)
	t.iconQuiet = CreateSheriffBadgeIcon(BadgePresetQuiet)
	t.iconFull = CreateSheriffBadgeIcon(BadgePresetFull)
	t.iconCustom = CreateSheriffBadgeIcon(BadgePresetCustom)

	if tbPtr, err := syscall.UTF16PtrFromString("TaskbarCreated"); err == nil {
		msgID, _, _ := procRegisterWindowMsgW.Call(uintptr(unsafe.Pointer(tbPtr)))
		t.taskbarCreatedMsg = uint32(msgID)
	}

	hInst, _, _ := procGetModuleHandleW.Call(0)
	clsName, _ := syscall.UTF16PtrFromString("ShieldSheriffTrayWndClass")

	wc := wndClassExW{
		Size:      uint32(unsafe.Sizeof(wndClassExW{})),
		WndProc:   syscall.NewCallback(trayWndProc),
		Instance:  hInst,
		ClassName: clsName,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	wndTitle, _ := syscall.UTF16PtrFromString("ShieldSheriff")
	hwnd, _, err := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(clsName)),
		uintptr(unsafe.Pointer(wndTitle)),
		0,
		0, 0, 0, 0,
		0, 0, hInst, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW failed: %v", err)
	}
	atomic.StoreUintptr(&t.hwnd, hwnd)
	defer atomic.StoreUintptr(&t.hwnd, 0)

	t.nid = notifyIconDataW{
		CbSize:           uint32(unsafe.Sizeof(notifyIconDataW{})),
		Hwnd:             hwnd,
		UID:              1,
		UFlags:           nifMessage | nifIcon | nifTip,
		UCallbackMessage: wmTrayCallback,
		HIcon:            t.iconPassive,
	}
	if !t.addIconWithRetry() {
		procDestroyWindow.Call(hwnd)
		return fmt.Errorf("Shell_NotifyIconW(NIM_ADD) failed")
	}

	t.ShowBalloon("ShieldSheriff", "Running in the system tray. Click to open settings, or right-click for quick actions.")

	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}

	procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
	return nil
}

func (t *AppTray) addIconWithRetry() bool {
	for i := 0; i < 3; i++ {
		if t.refreshIconAndTip(true) {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

// refreshIconAndTip updates the tray icon and tooltip. Must run on the tray UI thread.
func (t *AppTray) refreshIconAndTip(initial bool) bool {
	st, cfg, _, _ := t.gov.Snapshot()
	var icon uintptr
	if cfg.Pause.Active {
		icon = t.iconPause
	} else if cfg.Mode != defender.ModeActive {
		icon = t.iconPassive
	} else {
		switch cfg.Policy.PresetID {
		case "on-demand":
			icon = t.iconOnDemand
		case "workstation":
			icon = t.iconDev
		case "local-protection":
			icon = t.iconQuiet
		case "cloud-local":
			icon = t.iconFull
		default:
			icon = t.iconCustom
		}
	}
	tip := formatTrayTip(st, cfg)

	t.nid.HIcon = icon
	t.nid.UFlags = nifMessage | nifIcon | nifTip
	copyUTF16Fixed(t.nid.SzTip[:], tip)

	action := uintptr(nimModify)
	if initial {
		action = uintptr(nimAdd)
	}
	r1, _, _ := procShellNotifyIconW.Call(action, uintptr(unsafe.Pointer(&t.nid)))
	return r1 != 0
}

func formatTrayTip(st defender.Status, cfg sheriff.Config) string {
	if cfg.Pause.Active {
		return fmt.Sprintf("ShieldSheriff: Paused (%s)", cfg.Pause.Reason)
	}
	if cfg.Mode != defender.ModeActive {
		if cfg.Mode == defender.ModeUnconfigured {
			return "ShieldSheriff: Not Configured (Read-Only)"
		}
		return "ShieldSheriff: Passive Mode (Not Enforcing)"
	}
	name := defender.PresetDisplayName(cfg.Policy.PresetID)
	if !st.InCompliance || st.TamperProtectionActive {
		if st.TamperProtectionActive && len(st.DriftItems) == 0 {
			return fmt.Sprintf("ShieldSheriff: %s (Tamper Protection On)", name)
		}
		return fmt.Sprintf("ShieldSheriff: %s (%d Drift Item(s))", name, len(st.DriftItems))
	}
	return fmt.Sprintf("ShieldSheriff: %s", name)
}

// ShowBalloon safely schedules a tray notification to be displayed on the tray UI thread.
func (t *AppTray) ShowBalloon(title, body string) {
	h := atomic.LoadUintptr(&t.hwnd)
	if h == 0 {
		return
	}
	t.balloonMu.Lock()
	t.pendingBalloons = append(t.pendingBalloons, balloonMsg{title: title, body: body})
	t.balloonMu.Unlock()
	procPostMessageW.Call(h, wmShowBalloon, 0, 0)
}

// flushBalloons runs on the tray UI thread to display queued notifications safely.
func (t *AppTray) flushBalloons() {
	t.balloonMu.Lock()
	batch := t.pendingBalloons
	t.pendingBalloons = nil
	t.balloonMu.Unlock()

	for _, b := range batch {
		t.nid.UFlags = nifInfo
		copyUTF16Fixed(t.nid.SzInfoTitle[:], b.title)
		copyUTF16Fixed(t.nid.SzInfo[:], b.body)
		t.nid.DwInfoFlags = 0x00000001 // NIIF_INFO
		procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
	}
}

func copyUTF16Fixed(dst []uint16, s string) {
	for i := range dst {
		dst[i] = 0
	}
	u, err := syscall.UTF16FromString(s)
	if err != nil {
		return
	}
	if len(u) >= len(dst) {
		copy(dst, u[:len(dst)-1])
		dst[len(dst)-1] = 0
	} else {
		copy(dst, u)
	}
}

func trayWndProc(hwnd uintptr, msgID uint32, wParam, lParam uintptr) uintptr {
	t := activeTray
	if t == nil {
		r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msgID), wParam, lParam)
		return r
	}

	if t.taskbarCreatedMsg != 0 && msgID == t.taskbarCreatedMsg {
		t.refreshIconAndTip(true)
		return 0
	}

	switch msgID {
	case wmSyncTrayState:
		t.refreshIconAndTip(false)
		return 0

	case wmShowBalloon:
		t.flushBalloons()
		return 0

	case wmTrayCallback:
		low := uint32(lParam & 0xFFFF)
		switch low {
		case wmLButtonUp, wmLButtonDblClk:
			if t.openDashboard != nil {
				go t.openDashboard()
			}
			return 0
		case wmRButtonUp, wmContextMenu:
			t.showContextMenu()
			return 0
		}
		return 0

	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0

	case wmQueryEndSession:
		return 1

	case wmEndSession:
		if wParam != 0 {
			procDestroyWindow.Call(hwnd)
		}
		return 0

	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msgID), wParam, lParam)
	return r
}

func appendMenuItem(hMenu uintptr, flags uintptr, id uintptr, label string) {
	ptr, _ := syscall.UTF16PtrFromString(label)
	procAppendMenuW.Call(hMenu, flags, id, uintptr(unsafe.Pointer(ptr)))
}

func checkFlag(cond bool) uintptr {
	if cond {
		return mfString | mfChecked
	}
	return mfString
}

func (t *AppTray) showContextMenu() {
	st, cfg, _, _ := t.gov.Snapshot()

	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	appendMenuItem(hMenu, mfString, cmdOpenDashboard, "Open Dashboard")
	if !st.IsElevated {
		appendMenuItem(hMenu, mfString, cmdElevateNow, "Restart as Administrator")
	}
	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)

	// Presets derived from single source of truth
	for i, p := range t.presets {
		isActive := cfg.Mode == defender.ModeActive && cfg.Policy.PresetID == p.ID
		appendMenuItem(hMenu, checkFlag(isActive), uintptr(cmdPresetBase+i), p.ShortName)
	}

	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)

	// Pause Protection Submenu
	hPause, _, _ := procCreatePopupMenu.Call()
	if cfg.Pause.Active {
		appendMenuItem(hPause, mfString|mfChecked, cmdPauseResume, fmt.Sprintf("Resume Protection (%s)", cfg.Pause.Reason))
		procAppendMenuW.Call(hPause, mfSeparator, 0, 0)
	}
	appendMenuItem(hPause, mfString, cmdPause15m, "Pause for 15 Minutes")
	appendMenuItem(hPause, mfString, cmdPause30m, "Pause for 30 Minutes")
	appendMenuItem(hPause, mfString, cmdPause1h, "Pause for 1 Hour")
	appendMenuItem(hPause, mfString, cmdPause4h, "Pause for 4 Hours")
	procAppendMenuW.Call(hPause, mfSeparator, 0, 0)
	appendMenuItem(hPause, checkFlag(cfg.Mode != defender.ModeActive), cmdPassiveMode, "Passive Mode (Stop Enforcing)")
	appendMenuItem(hMenu, mfPopup, hPause, "Pause Protection")

	// Tools Submenu
	hActions, _, _ := procCreatePopupMenu.Call()
	appendMenuItem(hActions, mfString, cmdActionQuickScan, "Quick Scan")
	appendMenuItem(hActions, mfString, cmdActionSigUpdate, "Update Definitions")
	procAppendMenuW.Call(hActions, mfSeparator, 0, 0)
	appendMenuItem(hActions, mfString, cmdActionOpenWinSec, "Open Windows Security")
	appendMenuItem(hMenu, mfPopup, hActions, "Tools")

	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	appendMenuItem(hMenu, mfString, cmdExit, "Exit")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	h := atomic.LoadUintptr(&t.hwnd)
	procSetForegroundWin.Call(h)

	cmd, _, _ := procTrackPopupMenu.Call(
		hMenu,
		tpmRightButton|tpmReturnCmd,
		uintptr(pt.X),
		uintptr(pt.Y),
		0,
		h,
		0,
	)
	if cmd != 0 {
		t.handleCommand(uint32(cmd))
	}
}

func (t *AppTray) handleCommand(cmd uint32) {
	if cmd >= cmdPresetBase && int(cmd-cmdPresetBase) < len(t.presets) {
		preset := t.presets[cmd-cmdPresetBase]
		go func(p defender.Preset) {
			res, err := t.gov.ApplyPreset(p.ID)
			if err != nil {
				t.ShowBalloon("Preset Error", err.Error())
			} else if !res.Success && len(res.Warnings) > 0 {
				t.ShowBalloon("Preset Warning", res.Warnings[0])
			} else {
				t.ShowBalloon("Preset Applied", "Switched to "+p.ShortName)
			}
		}(preset)
		return
	}

	switch cmd {
	case cmdOpenDashboard:
		if t.openDashboard != nil {
			go t.openDashboard()
		}
	case cmdElevateNow:
		if err := defender.RelaunchElevated([]string{"ui", "--replace"}); err == nil {
			t.Quit()
		}

	case cmdPause15m:
		t.pauseFor(15*time.Minute, "15m Pause", "15 minutes")
	case cmdPause30m:
		t.pauseFor(30*time.Minute, "30m Pause", "30 minutes")
	case cmdPause1h:
		t.pauseFor(1*time.Hour, "1h Pause", "1 hour")
	case cmdPause4h:
		t.pauseFor(4*time.Hour, "4h Pause", "4 hours")

	case cmdPauseResume:
		go func() {
			res, err := t.gov.ResumePause()
			if err != nil {
				t.ShowBalloon("Resume Failed", err.Error())
			} else if !res.Success && len(res.Warnings) > 0 {
				t.ShowBalloon("Resume Warning", res.Warnings[0])
			} else {
				t.ShowBalloon("Protection Resumed", "Restored configured protection settings.")
			}
		}()

	case cmdPassiveMode:
		go func() {
			res, err := t.gov.EnterPassiveMode()
			if err != nil {
				t.ShowBalloon("Passive Mode Error", err.Error())
			} else if !res.Success && len(res.Warnings) > 0 {
				t.ShowBalloon("Passive Mode Warning", "Stopped enforcing, but revert reported: "+res.Warnings[0])
			} else {
				t.ShowBalloon("Passive Mode", "Stopped enforcing and reverted ShieldSheriff changes.")
			}
		}()

	case cmdActionQuickScan:
		go func() {
			t.ShowBalloon("Quick Scan Started", "Running background quick scan...")
			if _, err := defender.RunQuickScan(); err != nil {
				t.ShowBalloon("Quick Scan Failed", err.Error())
			} else {
				t.ShowBalloon("Quick Scan Complete", "No threats detected.")
			}
		}()
	case cmdActionSigUpdate:
		go func() {
			t.ShowBalloon("Updating Definitions", "Requesting latest signatures via MpCmdRun.exe...")
			if _, err := defender.UpdateSignatures(); err != nil {
				t.ShowBalloon("Definition Update Failed", err.Error())
			} else {
				t.ShowBalloon("Definitions Updated", "Defender virus definitions are up to date.")
			}
		}()
	case cmdActionOpenWinSec:
		_ = defender.OpenWindowsSecuritySettings()

	case cmdExit:
		if h := atomic.LoadUintptr(&t.hwnd); h != 0 {
			procDestroyWindow.Call(h)
		} else {
			procPostQuitMessage.Call(0)
		}
	}
}

func (t *AppTray) pauseFor(dur time.Duration, reason, label string) {
	go func() {
		res, err := t.gov.StartPause(dur, reason)
		if err != nil {
			t.ShowBalloon("Pause Failed", err.Error())
		} else if !res.Success && len(res.Warnings) > 0 {
			t.ShowBalloon("Pause Warning", res.Warnings[0])
		} else {
			t.ShowBalloon("Protection Paused", "Real-Time Protection paused for "+label+".")
		}
	}()
}
