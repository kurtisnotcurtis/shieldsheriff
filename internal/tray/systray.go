package tray

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"shieldsheriff/internal/defender"
	"shieldsheriff/internal/sheriff"
)

var (
	modShell32            = syscall.NewLazyDLL("shell32.dll")
	modKernel32           = syscall.NewLazyDLL("kernel32.dll")
	procShellNotifyIconW  = modShell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW  = modKernel32.NewProc("GetModuleHandleW")
	procRegisterClassExW  = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW   = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW    = modUser32.NewProc("DefWindowProcW")
	procGetMessageW       = modUser32.NewProc("GetMessageW")
	procTranslateMessage  = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW  = modUser32.NewProc("DispatchMessageW")
	procPostQuitMessage   = modUser32.NewProc("PostQuitMessage")
	procPostMessageW      = modUser32.NewProc("PostMessageW")
	procDestroyWindow     = modUser32.NewProc("DestroyWindow")
	procCreatePopupMenu   = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW       = modUser32.NewProc("AppendMenuW")
	procDestroyMenu       = modUser32.NewProc("DestroyMenu")
	procTrackPopupMenu    = modUser32.NewProc("TrackPopupMenu")
	procSetForegroundWin  = modUser32.NewProc("SetForegroundWindow")
	procGetCursorPos      = modUser32.NewProc("GetCursorPos")
)

const (
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
	wmCommand         = 0x0111
	wmUser            = 0x0400
	wmTrayCallback  = wmUser + 1
	wmSyncTrayState = wmUser + 2

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
	mfGrayed    = 0x00000001
	mfSeparator = 0x00000800

	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
)

// Menu command IDs
const (
	cmdOpenDashboard = 1001
	cmdElevateNow    = 1002

	cmdPresetQuietGuardian = 1010
	cmdPresetDevWork       = 1011
	cmdPresetOnDemand      = 1012
	cmdPresetFullShield    = 1013

	cmdToggleRealtime = 1020
	cmdToggleBehavior = 1021
	cmdToggleIOAV     = 1022
	cmdToggleScript   = 1023
	cmdToggleCloud    = 1024
	cmdToggleSamples  = 1025

	cmdToggleSuppressNags = 1030
	cmdToggleMuteSystray  = 1031

	cmdStandDown15m    = 1040
	cmdStandDown30m    = 1041
	cmdStandDown1h     = 1042
	cmdStandDown4h     = 1043
	cmdStandDownResume = 1044

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

// AppTray manages the native Win32 System Tray icon and context menu for ShieldSheriff.
type AppTray struct {
	gov           *sheriff.Governor
	openDashboard func()
	serverURL     string
	hwnd          uintptr
	iconGold      uintptr
	iconStandDown uintptr
	iconWarn      uintptr
	nid           notifyIconDataW
}

var activeTray *AppTray

// NewAppTray constructs the System Tray controller.
func NewAppTray(gov *sheriff.Governor, openDashboard func()) *AppTray {
	t := &AppTray{
		gov:           gov,
		openDashboard: openDashboard,
	}
	gov.SetOnStateSync(func(_ defender.DeputyStatus, _ defender.StandingOrders, _ defender.StandDownState) {
		if t.hwnd != 0 {
			procPostMessageW.Call(t.hwnd, wmSyncTrayState, 0, 0)
		}
	})
	return t
}

// SetServerURL sets the Command Center URL displayed in tray status indicators.
func (t *AppTray) SetServerURL(url string) {
	t.serverURL = strings.TrimSpace(url)
	if t.hwnd != 0 {
		procPostMessageW.Call(t.hwnd, wmSyncTrayState, 0, 0)
	}
}

// Quit requests the system tray message loop to exit cleanly.
func (t *AppTray) Quit() {
	if t.hwnd != 0 {
		procPostMessageW.Call(t.hwnd, wmClose, 0, 0)
	}
}

// Run starts the Win32 System Tray message loop on the current goroutine.
func (t *AppTray) Run() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	activeTray = t
	t.iconGold = CreateSheriffBadgeIcon(BadgeGold)
	t.iconStandDown = CreateSheriffBadgeIcon(BadgeStandDown)
	t.iconWarn = CreateSheriffBadgeIcon(BadgeWarning)

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
	t.hwnd = hwnd

	t.nid = notifyIconDataW{
		CbSize:           uint32(unsafe.Sizeof(notifyIconDataW{})),
		Hwnd:             hwnd,
		UID:              1,
		UFlags:           nifMessage | nifIcon | nifTip,
		UCallbackMessage: wmTrayCallback,
		HIcon:            t.iconGold,
	}
	t.refreshIconAndTip(true)

	startupMsg := "Running in the background. Right-click the shield icon for options or to exit."
	if t.serverURL != "" {
		startupMsg = fmt.Sprintf("Command Center running at %s. Right-click the shield icon for options or to exit.", t.serverURL)
	}
	t.ShowBalloon("ShieldSheriff Running", startupMsg)

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

func (t *AppTray) refreshIconAndTip(initial bool) {
	st, ord, sd, _, _ := t.gov.Snapshot()
	var icon uintptr
	if sd.Active {
		icon = t.iconStandDown
	} else if !st.InCompliance || st.TamperProtectionActive {
		icon = t.iconWarn
	} else {
		icon = t.iconGold
	}
	tip := formatTrayTip(t.serverURL, st, ord, sd)

	t.nid.HIcon = icon
	t.nid.UFlags = nifMessage | nifIcon | nifTip
	copyUTF16Fixed(t.nid.SzTip[:], tip)

	action := uintptr(nimModify)
	if initial {
		action = uintptr(nimAdd)
	}
	procShellNotifyIconW.Call(action, uintptr(unsafe.Pointer(&t.nid)))
}

func formatTrayTip(serverURL string, st defender.DeputyStatus, ord defender.StandingOrders, sd defender.StandDownState) string {
	addrSuffix := ""
	if hostPort := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(serverURL), "http://"), "https://"); hostPort != "" {
		addrSuffix = " (" + hostPort + ")"
	}
	if sd.Active {
		return fmt.Sprintf("ShieldSheriff — Running%s | Standing Down (%s)", addrSuffix, sd.Reason)
	}
	if !st.InCompliance || st.TamperProtectionActive {
		return fmt.Sprintf("ShieldSheriff — Running%s | %d Drift Item(s) | %s", addrSuffix, len(st.DriftItems), ord.PresetName)
	}
	rtp := "ON"
	if !st.RealtimeProtection {
		rtp = "OFF"
	}
	return fmt.Sprintf("ShieldSheriff ★ Running%s | Real-Time: %s | Nags: Silenced", addrSuffix, rtp)
}

func formatTrayStatusLabel(serverURL string, st defender.DeputyStatus) string {
	label := "● ShieldSheriff Running"
	if hostPort := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(serverURL), "http://"), "https://"); hostPort != "" {
		label = "● Running — " + hostPort
	}
	if st.IsElevated {
		return label + " (Admin)"
	}
	return label + " (Read-Only)"
}

// ShowBalloon displays a subtle tray notification from ShieldSheriff itself.
func (t *AppTray) ShowBalloon(title, body string) {
	if t.hwnd == 0 {
		return
	}
	t.nid.UFlags = nifInfo
	copyUTF16Fixed(t.nid.SzInfoTitle[:], title)
	copyUTF16Fixed(t.nid.SzInfo[:], body)
	t.nid.DwInfoFlags = 0x00000001 // NIIF_INFO
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
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

	switch msgID {
	case wmSyncTrayState:
		t.refreshIconAndTip(false)
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
	st, ord, sd, _, _ := t.gov.Snapshot()

	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	appendMenuItem(hMenu, mfString|mfGrayed, 0, formatTrayStatusLabel(t.serverURL, st))
	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)

	appendMenuItem(hMenu, mfString, cmdOpenDashboard, "★ Open ShieldSheriff Command Center")
	if !st.IsElevated {
		appendMenuItem(hMenu, mfString, cmdElevateNow, "⚡ Relaunch as Administrator (Required to Enforce)")
	}
	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)

	// Presets Submenu
	hPresets, _, _ := procCreatePopupMenu.Call()
	appendMenuItem(hPresets, checkFlag(ord.PresetName == "quiet-guardian"), cmdPresetQuietGuardian, "Quiet Guardian (Real-Time ON, Cloud/Samples/Nags OFF)")
	appendMenuItem(hPresets, checkFlag(ord.PresetName == "dev-workstation"), cmdPresetDevWork, "Developer Workstation (Fast Builds + Auto Stand-Down)")
	appendMenuItem(hPresets, checkFlag(ord.PresetName == "on-demand-only"), cmdPresetOnDemand, "On-Demand Deputy (Real-Time OFF Permanently, No Nags)")
	appendMenuItem(hPresets, checkFlag(ord.PresetName == "full-shield-no-nag"), cmdPresetFullShield, "Full Local + Cloud Shield (Nag-Free)")
	appendMenuItem(hMenu, mfPopup, hPresets, "Standing Order Presets")

	// Granular Engine Toggles
	hEngines, _, _ := procCreatePopupMenu.Call()
	appendMenuItem(hEngines, checkFlag(ord.RealtimeProtection), cmdToggleRealtime, "Real-Time File Protection")
	appendMenuItem(hEngines, checkFlag(ord.BehaviorMonitoring), cmdToggleBehavior, "Behavior Monitoring")
	appendMenuItem(hEngines, checkFlag(ord.IOAVProtection), cmdToggleIOAV, "Downloaded Files & Attachments (IOAV)")
	appendMenuItem(hEngines, checkFlag(ord.ScriptScanning), cmdToggleScript, "Script Scanning (AMSI)")
	procAppendMenuW.Call(hEngines, mfSeparator, 0, 0)
	appendMenuItem(hEngines, checkFlag(ord.CloudProtection > 0), cmdToggleCloud, "Cloud-Delivered Protection (MAPS)")
	appendMenuItem(hEngines, checkFlag(ord.SampleSubmission == 1 || ord.SampleSubmission == 3), cmdToggleSamples, "Automatic Sample Submission")
	appendMenuItem(hMenu, mfPopup, hEngines, "Granular Deputy Toggles")

	// Keep the Peace (Nag Control)
	appendMenuItem(hMenu, checkFlag(ord.SuppressAllNags), cmdToggleSuppressNags, "Keep the Peace (Silence All Security Nags)")
	appendMenuItem(hMenu, checkFlag(ord.MuteWindowsSecSystray), cmdToggleMuteSystray, "Hide Default Windows Security Tray Icon")

	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)

	// Deputy Stand-Down Submenu
	hStandDown, _, _ := procCreatePopupMenu.Call()
	if sd.Active {
		appendMenuItem(hStandDown, mfString|mfChecked, cmdStandDownResume, fmt.Sprintf("Active: %s — Click to Resume Now", sd.Reason))
		procAppendMenuW.Call(hStandDown, mfSeparator, 0, 0)
	}
	appendMenuItem(hStandDown, mfString, cmdStandDown15m, "Stand Down for 15 Minutes")
	appendMenuItem(hStandDown, mfString, cmdStandDown30m, "Stand Down for 30 Minutes")
	appendMenuItem(hStandDown, mfString, cmdStandDown1h, "Stand Down for 1 Hour")
	appendMenuItem(hStandDown, mfString, cmdStandDown4h, "Stand Down for 4 Hours")
	appendMenuItem(hMenu, mfPopup, hStandDown, "Deputy Stand-Down (Temporary Pause)")

	// Deputy Actions Submenu
	hActions, _, _ := procCreatePopupMenu.Call()
	appendMenuItem(hActions, mfString, cmdActionQuickScan, "Run On-Demand Quick Scan")
	appendMenuItem(hActions, mfString, cmdActionSigUpdate, "Update Virus Definitions")
	procAppendMenuW.Call(hActions, mfSeparator, 0, 0)
	appendMenuItem(hActions, mfString, cmdActionOpenWinSec, "Open Windows Security (Tamper Protection Toggle)")
	appendMenuItem(hMenu, mfPopup, hActions, "Deputy Actions")

	procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	appendMenuItem(hMenu, mfString, cmdExit, "Exit ShieldSheriff (Stop Server & Tray)")

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWin.Call(t.hwnd)

	cmd, _, _ := procTrackPopupMenu.Call(
		hMenu,
		tpmRightButton|tpmReturnCmd,
		uintptr(pt.X),
		uintptr(pt.Y),
		0,
		t.hwnd,
		0,
	)
	if cmd != 0 {
		t.handleCommand(uint32(cmd))
	}
}

func (t *AppTray) handleCommand(cmd uint32) {
	_, ord, _, _, _ := t.gov.Snapshot()

	switch cmd {
	case cmdOpenDashboard:
		if t.openDashboard != nil {
			go t.openDashboard()
		}
	case cmdElevateNow:
		if err := defender.RelaunchElevated([]string{"ui", "--replace"}); err == nil {
			t.Quit()
		}

	case cmdPresetQuietGuardian, cmdPresetDevWork, cmdPresetOnDemand, cmdPresetFullShield:
		targetID := map[uint32]string{
			cmdPresetQuietGuardian: "quiet-guardian",
			cmdPresetDevWork:       "dev-workstation",
			cmdPresetOnDemand:      "on-demand-only",
			cmdPresetFullShield:    "full-shield-no-nag",
		}[cmd]
		for _, p := range defender.BuiltinPresets() {
			if p.ID == targetID {
				go func(preset defender.Preset) {
					_, _ = t.gov.UpdateOrders(preset.Orders)
					t.ShowBalloon("Standing Orders Updated", "Activated preset: "+preset.Name)
				}(p)
				break
			}
		}

	case cmdToggleRealtime:
		ord.RealtimeProtection = !ord.RealtimeProtection
		ord.PresetName = "custom"
		go t.gov.UpdateOrders(ord)
	case cmdToggleBehavior:
		ord.BehaviorMonitoring = !ord.BehaviorMonitoring
		ord.PresetName = "custom"
		go t.gov.UpdateOrders(ord)
	case cmdToggleIOAV:
		ord.IOAVProtection = !ord.IOAVProtection
		ord.PresetName = "custom"
		go t.gov.UpdateOrders(ord)
	case cmdToggleScript:
		ord.ScriptScanning = !ord.ScriptScanning
		ord.PresetName = "custom"
		go t.gov.UpdateOrders(ord)
	case cmdToggleCloud:
		if ord.CloudProtection > 0 {
			ord.CloudProtection = 0
		} else {
			ord.CloudProtection = 2
		}
		ord.PresetName = "custom"
		go t.gov.UpdateOrders(ord)
	case cmdToggleSamples:
		if ord.SampleSubmission == 2 {
			ord.SampleSubmission = 1
		} else {
			ord.SampleSubmission = 2
		}
		ord.PresetName = "custom"
		go t.gov.UpdateOrders(ord)

	case cmdToggleSuppressNags:
		ord.SuppressAllNags = !ord.SuppressAllNags
		ord.SuppressEnhancedNags = ord.SuppressAllNags
		go t.gov.UpdateOrders(ord)
	case cmdToggleMuteSystray:
		ord.MuteWindowsSecSystray = !ord.MuteWindowsSecSystray
		go t.gov.UpdateOrders(ord)

	case cmdStandDown15m:
		go func() {
			t.gov.StartStandDown(15*time.Minute, "15m Manual Stand-Down")
			t.ShowBalloon("Deputy Standing Down", "Real-Time Protection paused for 15 minutes.")
		}()
	case cmdStandDown30m:
		go func() {
			t.gov.StartStandDown(30*time.Minute, "30m Manual Stand-Down")
			t.ShowBalloon("Deputy Standing Down", "Real-Time Protection paused for 30 minutes.")
		}()
	case cmdStandDown1h:
		go func() {
			t.gov.StartStandDown(1*time.Hour, "1h Manual Stand-Down")
			t.ShowBalloon("Deputy Standing Down", "Real-Time Protection paused for 1 hour.")
		}()
	case cmdStandDown4h:
		go func() {
			t.gov.StartStandDown(4*time.Hour, "4h Manual Stand-Down")
			t.ShowBalloon("Deputy Standing Down", "Real-Time Protection paused for 4 hours.")
		}()
	case cmdStandDownResume:
		go func() {
			t.gov.ResumeFromStandDown()
			t.ShowBalloon("Deputy Back on Duty", "Restored Standing Orders.")
		}()

	case cmdActionQuickScan:
		go func() {
			t.ShowBalloon("Deputy Quick Scan Started", "Running background quick scan via MpCmdRun.exe...")
			if _, err := defender.RunQuickScan(); err == nil {
				t.ShowBalloon("Deputy Quick Scan Complete", "No threats detected.")
			}
		}()
	case cmdActionSigUpdate:
		go func() {
			t.ShowBalloon("Updating Definitions", "Requesting latest signatures via MpCmdRun.exe...")
			if _, err := defender.UpdateSignatures(); err == nil {
				t.ShowBalloon("Definitions Updated", "Defender virus definitions are up to date.")
			}
		}()
	case cmdActionOpenWinSec:
		_ = defender.OpenWindowsSecuritySettings()

	case cmdExit:
		if t.hwnd != 0 {
			procDestroyWindow.Call(t.hwnd)
		} else {
			procPostQuitMessage.Call(0)
		}
	}
}
