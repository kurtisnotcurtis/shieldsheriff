package sheriff

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

const ServiceName = "ShieldSheriff"
const ServiceDisplayName = "ShieldSheriff Defender Governor"
const ServiceDescription = "User-elected orchestrator that enforces granular Windows Defender Standing Orders and suppresses Windows Security nags."

var (
	modAdvapi32                       = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDispatcherW   = modAdvapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = modAdvapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = modAdvapi32.NewProc("SetServiceStatus")
)

const (
	serviceWin32OwnProcess = 0x00000010
	serviceAcceptStop      = 0x00000001
	serviceAcceptShutdown  = 0x00000004

	serviceStartPending = 0x00000002
	serviceRunning      = 0x00000004
	serviceStopPending  = 0x00000003
	serviceStopped      = 0x00000001

	serviceControlStop        = 0x00000001
	serviceControlInterrogate = 0x00000004
	serviceControlShutdown    = 0x00000005
)

type serviceTableEntryW struct {
	ServiceName *uint16
	ServiceProc uintptr
}

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

var (
	svcStatusHandle uintptr
	svcStopCh       chan struct{}
	svcGovernor     *Governor
)

func serviceCtrlHandler(control, eventType uint32, eventData, context uintptr) uintptr {
	switch control {
	case serviceControlStop, serviceControlShutdown:
		updateSvcStatus(serviceStopPending, 0, 3000)
		select {
		case <-svcStopCh:
		default:
			close(svcStopCh)
		}
		return 0
	case serviceControlInterrogate:
		return 0
	}
	return 0
}

func updateSvcStatus(state uint32, checkPoint uint32, waitHint uint32) {
	if svcStatusHandle == 0 {
		return
	}
	st := serviceStatus{
		ServiceType:      serviceWin32OwnProcess,
		CurrentState:     state,
		ControlsAccepted: serviceAcceptStop | serviceAcceptShutdown,
		Win32ExitCode:    0,
		CheckPoint:       checkPoint,
		WaitHint:         waitHint,
	}
	if state == serviceStartPending || state == serviceStopped {
		st.ControlsAccepted = 0
	}
	procSetServiceStatus.Call(svcStatusHandle, uintptr(unsafe.Pointer(&st)))
}

func serviceMain(argc uint32, argv **uint16) uintptr {
	svcStopCh = make(chan struct{})
	namePtr, _ := syscall.UTF16PtrFromString(ServiceName)
	h, _, _ := procRegisterServiceCtrlHandlerExW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		syscall.NewCallback(serviceCtrlHandler),
		0,
	)
	svcStatusHandle = h
	updateSvcStatus(serviceStartPending, 1, 3000)

	svcGovernor = NewGovernor()
	svcGovernor.EnforceNow()
	svcGovernor.StartLoop()

	updateSvcStatus(serviceRunning, 0, 0)
	<-svcStopCh

	svcGovernor.StopLoop()
	updateSvcStatus(serviceStopped, 0, 0)
	return 0
}

// RunWindowsService runs the Windows Service dispatcher when invoked by services.exe (`shieldsheriff service run`).
func RunWindowsService() error {
	namePtr, _ := syscall.UTF16PtrFromString(ServiceName)
	table := [2]serviceTableEntryW{
		{
			ServiceName: namePtr,
			ServiceProc: syscall.NewCallback(serviceMain),
		},
		{
			ServiceName: nil,
			ServiceProc: 0,
		},
	}
	r1, _, err := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if r1 == 0 {
		return fmt.Errorf("StartServiceCtrlDispatcherW failed: %v", err)
	}
	return nil
}

func scCommand(args ...string) *exec.Cmd {
	cmd := exec.Command("sc.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}

// InstallService registers and starts ShieldSheriff as an automatic SYSTEM Windows Service.
func InstallService() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	binPath := fmt.Sprintf(`"%s" service run`, exe)

	createCmd := scCommand("create", ServiceName,
		"binPath=", binPath,
		"DisplayName=", ServiceDisplayName,
		"start=", "auto",
	)
	out, err := createCmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "1073") { // 1073 = already exists
		return strings.TrimSpace(string(out)), err
	}

	_ = scCommand("description", ServiceName, ServiceDescription).Run()
	startOut, startErr := scCommand("start", ServiceName).CombinedOutput()
	if startErr != nil && !strings.Contains(string(startOut), "1056") { // 1056 = already running
		return strings.TrimSpace(string(startOut)), startErr
	}
	return "ShieldSheriff SYSTEM Service installed and running.", nil
}

// UninstallService stops and removes the ShieldSheriff Windows Service.
func UninstallService() (string, error) {
	_ = scCommand("stop", ServiceName).Run()
	out, err := scCommand("delete", ServiceName).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
