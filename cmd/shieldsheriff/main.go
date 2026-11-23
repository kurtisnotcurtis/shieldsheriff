//go:generate go run github.com/tc-hib/go-winres@latest make --in winres/winres.json --out rsrc --arch amd64,arm64

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"shieldsheriff/internal/defender"
	"shieldsheriff/internal/sheriff"
	"shieldsheriff/internal/tray"
	"shieldsheriff/internal/ui"
	"shieldsheriff/internal/version"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		runStatus(nil)
		fmt.Println("  Launch UI / Tray : shieldsheriff ui [--elevate]  |  shieldsheriff tray [--elevate]")
		fmt.Println("  All Commands     : shieldsheriff help")
		return
	}

	cmd, opts := parseInteractiveCommand(args)
	switch cmd {
	case "tray", "--minimized":
		runInteractive(false, opts.replace, opts.elevate)
	case "ui", "dashboard":
		runInteractive(true, opts.replace, opts.elevate)
	case "status":
		runStatus(args[1:])
	case "apply":
		runApply(args[1:])
	case "set":
		runSet(args[1:])
	case "pause":
		runPause(args[1:])
	case "resume":
		runResume()
	case "scan":
		runScan()
	case "update":
		runUpdate()
	case "service":
		runService(args[1:])
	case "version", "-v", "--version":
		runVersion(args[1:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

type interactiveOptions struct {
	replace bool
	elevate bool
}

func parseInteractiveCommand(args []string) (string, interactiveOptions) {
	if len(args) == 0 {
		return "", interactiveOptions{}
	}
	cmd := strings.ToLower(args[0])
	opts := interactiveOptions{
		replace: hasFlag(args[1:], "--replace"),
		elevate: (hasFlag(args, "--elevate") || hasFlag(args, "-e")) && !hasFlag(args[1:], "--no-elevate"),
	}
	return cmd, opts
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if strings.EqualFold(a, flag) {
			return true
		}
	}
	return false
}

func runInteractive(openWindowOnStart bool, replaceExisting bool, wantElevate bool) {
	suppressOwnedConsoleWindow()

	const instanceMutexName = `Local\ShieldSheriffCommandCenterInstance`
	const preferredPort = 38419

	var (
		release        func()
		alreadyRunning bool
		err            error
	)
	attempts := 1
	if replaceExisting {
		attempts = 20
	}
	for i := 0; i < attempts; i++ {
		release, alreadyRunning, err = acquireSingleInstance(instanceMutexName)
		if err != nil || !alreadyRunning {
			break
		}
		if replaceExisting && i < attempts-1 {
			time.Sleep(150 * time.Millisecond)
		}
	}
	if err == nil && alreadyRunning {
		if openWindowOnStart {
			_ = focusExistingInstance(preferredPort)
		}
		fmt.Println("ShieldSheriff is already running.")
		return
	}
	if release != nil {
		defer release()
	}

	if !defender.IsProcessElevated() && wantElevate {
		mode := "ui"
		if !openWindowOnStart {
			mode = "tray"
		}
		if err := defender.RelaunchElevated([]string{mode, "--replace"}); err == nil {
			return
		}
	}

	gov := sheriff.NewGovernor()
	st, ord, _, _, _ := gov.Snapshot()
	if !st.IsElevated {
		if !openWindowOnStart {
			fmt.Fprintln(os.Stderr, "System Tray mode requires Administrator privileges. Run `shieldsheriff tray --elevate` (or launch from an elevated shell).")
			os.Exit(1)
		}
		runReadOnlyUI(gov, preferredPort)
		return
	}

	if ord.Elected && !st.TamperProtectionActive {
		gov.EnforceNow()
	}
	gov.StartLoop()
	defer gov.StopLoop()

	srv, err := ui.StartServer(gov, preferredPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start Dashboard UI server: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("ShieldSheriff Dashboard running at %s\n", srv.URL())
	if openWindowOnStart {
		go func() {
			time.Sleep(250 * time.Millisecond)
			srv.OpenWindow()
		}()
	}

	appTray := tray.NewAppTray(gov, func() {
		srv.OpenWindow()
	})
	appTray.SetServerURL(srv.URL())
	srv.SetOnShutdown(appTray.Quit)

	if ord.Elected && ord.CheckUpdatesOnStart {
		go func() {
			info := gov.CheckForUpdates()
			if info.Available {
				appTray.ShowBalloon("ShieldSheriff Update Available", fmt.Sprintf("Version v%s is available (current v%s).", info.LatestVersion, info.CurrentVersion))
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		appTray.Quit()
	}()

	trayErr := appTray.Run()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(shutdownCtx)
	cancel()
	gov.StopLoop()

	if trayErr != nil {
		fmt.Fprintf(os.Stderr, "System tray error: %v\n", trayErr)
		os.Exit(1)
	}
}

func runReadOnlyUI(gov *sheriff.Governor, preferredPort int) {
	srv, err := ui.StartServer(gov, preferredPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start Dashboard UI server: %v\n", err)
		os.Exit(1)
	}

	doneCh := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() {
		closeOnce.Do(func() {
			close(doneCh)
		})
	}

	srv.SetOnShutdown(closeDone)
	srv.SetOnWindowClosed(closeDone)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			closeDone()
		case <-doneCh:
		}
	}()

	fmt.Printf("ShieldSheriff Dashboard (Read-Only) running at %s\n", srv.URL())
	srv.OpenWindow()

	<-doneCh
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = srv.Shutdown(shutdownCtx)
	cancel()
}

func runStatus(args []string) {
	gov := sheriff.NewGovernor()
	st, ord, sd, _, cfgPath := gov.Snapshot()

	for _, a := range args {
		if a == "--json" || a == "-j" {
			out, _ := json.MarshalIndent(map[string]any{
				"version":    version.Info(),
				"status":     st,
				"orders":     ord,
				"standDown":  sd,
				"configPath": cfgPath,
			}, "", "  ")
			fmt.Println(string(out))
			return
		}
	}

	fmt.Println("================================================================")
	fmt.Printf("  SHIELDSHERIFF v%s (%s) - DEFENDER STATUS & CONFIGURATION\n", version.Version, version.Codename)
	fmt.Println("================================================================")
	fmt.Printf("  Privilege Level     : %s\n", map[bool]string{true: "Elevated (Administrator / SYSTEM)", false: "Standard User (Read-Only)"}[st.IsElevated])
	fmt.Printf("  Configuration       : %s (%s)\n", ord.PresetName, cfgPath)
	fmt.Printf("  Defender Service    : %s (Platform %s | Signatures %s)\n",
		map[bool]string{true: "RUNNING", false: "STOPPED"}[st.ServiceRunning],
		st.PlatformVersion, st.SignatureVersion)
	fmt.Printf("  Tamper Protection   : %s (raw=0x%x)\n",
		map[bool]string{true: "ON  [Blocks policy writes - toggle OFF once in Windows Security]", false: "OFF [Ready for ShieldSheriff]"}[st.TamperProtectionActive],
		st.TamperProtectionRaw)
	if sd.Active {
		fmt.Printf("  Pause Status        : ACTIVE (%s)\n", sd.Reason)
	}
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("  SETTING                         LIVE STATE          CONFIGURED")
	fmt.Println("----------------------------------------------------------------")
	printRow := func(name, live, order string) {
		fmt.Printf("  %-30s  %-18s  %s\n", name, live, order)
	}
	onOff := func(b bool) string {
		if b {
			return "ON"
		}
		return "OFF"
	}
	printRow("Real-Time Protection", onOff(st.RealtimeProtection), onOff(ord.RealtimeProtection))
	printRow("Behavior Monitoring", onOff(st.BehaviorMonitoring), onOff(ord.BehaviorMonitoring))
	printRow("Downloaded Files (IOAV)", onOff(st.IOAVProtection), onOff(ord.IOAVProtection))
	printRow("Script Scanning (AMSI)", onOff(st.ScriptScanning), onOff(ord.ScriptScanning))
	printRow("Network Protection", fmt.Sprintf("Mode %d", st.NetworkProtection), fmt.Sprintf("Mode %d", ord.NetworkProtection))
	printRow("Cloud Protection (MAPS)", fmt.Sprintf("Mode %d (%s)", st.CloudProtection, map[bool]string{true: "OFF", false: "ON"}[st.CloudProtection == 0]), fmt.Sprintf("Mode %d", ord.CloudProtection))
	printRow("Sample Submission", fmt.Sprintf("Mode %d (%s)", st.SampleSubmission, map[bool]string{true: "Never/OFF", false: "Active"}[st.SampleSubmission == 2]), fmt.Sprintf("Mode %d", ord.SampleSubmission))
	printRow("Security Center Nags", map[bool]string{true: "SILENCED", false: "ACTIVE (Nagging)"}[st.NagsSuppressed], map[bool]string{true: "SILENCED", false: "Allow"}[ord.SuppressAllNags])
	printRow("Windows Security Tray Icon", map[bool]string{true: "MUTED", false: "VISIBLE"}[st.SecurityTrayIconMuted], map[bool]string{true: "MUTED", false: "VISIBLE"}[ord.MuteWindowsSecSystray])
	fmt.Println("----------------------------------------------------------------")
	if st.InCompliance {
		fmt.Println("  COMPLIANCE: IN COMPLIANCE")
	} else {
		fmt.Printf("  COMPLIANCE: ! %d DRIFT ITEM(S) DETECTED:\n", len(st.DriftItems))
		for _, d := range st.DriftItems {
			fmt.Printf("    - %s\n", d)
		}
		if !st.IsElevated {
			fmt.Println("\n  Tip: Run `shieldsheriff apply --elevate` to apply configuration as Administrator.")
		}
	}
	fmt.Println("================================================================")
}

func runApply(args []string) {
	gov := sheriff.NewGovernor()
	_, ord, _, _, _ := gov.Snapshot()

	wantElevate := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--elevate" || a == "-e" {
			wantElevate = true
		} else if (a == "--preset" || a == "-p") && i+1 < len(args) {
			i++
			presetID := strings.ToLower(args[i])
			found := false
			for _, p := range defender.BuiltinPresets() {
				if p.ID == presetID {
					ord = p.Orders
					found = true
					break
				}
			}
			if !found {
				fmt.Fprintf(os.Stderr, "Unknown preset %q. Available: cloud-local, local-protection, workstation, on-demand\n", presetID)
				os.Exit(1)
			}
		}
	}

	if !defender.IsProcessElevated() && wantElevate {
		_, _ = sheriff.SaveOrders(ord)
		fmt.Println("Requesting Administrator privileges via UAC to apply configuration...")
		if err := defender.RelaunchElevated([]string{"apply"}); err != nil {
			fmt.Fprintf(os.Stderr, "Elevation failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	res, err := gov.UpdateOrders(ord)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Note saving settings: %v\n", err)
	}
	for _, a := range res.Applied {
		fmt.Printf("  [✓] %s\n", a)
	}
	for _, w := range res.Warnings {
		fmt.Printf("  [!] %s\n", w)
	}
	runStatus(nil)
}

func runSet(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: shieldsheriff set <key>=<value> [key=value ...]")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  shieldsheriff set realtime=on cloud=off samples=off nags=off")
		fmt.Fprintln(os.Stderr, "  shieldsheriff set behavior=off script=off systray=mute")
		os.Exit(1)
	}

	gov := sheriff.NewGovernor()
	_, ord, _, _, _ := gov.Snapshot()
	ord.PresetName = "custom"

	parseBool := func(v string) bool {
		v = strings.ToLower(strings.TrimSpace(v))
		return v == "on" || v == "true" || v == "1" || v == "yes" || v == "enabled"
	}

	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Invalid key=value pair: %q\n", arg)
			os.Exit(1)
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		v := strings.ToLower(strings.TrimSpace(parts[1]))

		switch k {
		case "realtime", "rtp":
			ord.RealtimeProtection = parseBool(v)
		case "behavior", "bm":
			ord.BehaviorMonitoring = parseBool(v)
		case "ioav", "downloads":
			ord.IOAVProtection = parseBool(v)
		case "script", "amsi":
			ord.ScriptScanning = parseBool(v)
		case "network", "net":
			switch v {
			case "off", "0", "false":
				ord.NetworkProtection = 0
			case "on", "block", "1", "true":
				ord.NetworkProtection = 1
			case "audit", "2":
				ord.NetworkProtection = 2
			}
		case "cloud", "maps", "spynet":
			switch v {
			case "off", "0", "false":
				ord.CloudProtection = 0
			case "basic", "1":
				ord.CloudProtection = 1
			case "advanced", "on", "2", "true":
				ord.CloudProtection = 2
			}
		case "samples", "submit":
			switch v {
			case "off", "never", "2", "false":
				ord.SampleSubmission = 2
			case "prompt", "0":
				ord.SampleSubmission = 0
			case "safe", "1", "on", "true":
				ord.SampleSubmission = 1
			case "all", "3":
				ord.SampleSubmission = 3
			}
		case "nags", "notifications":
			// nags=off means SuppressAllNags=true
			if v == "off" || v == "silence" || v == "mute" || v == "suppressed" || v == "0" {
				ord.SuppressAllNags = true
				ord.SuppressEnhancedNags = true
			} else {
				ord.SuppressAllNags = false
				ord.SuppressEnhancedNags = false
			}
		case "systray", "tray-nag":
			if v == "mute" || v == "hide" || v == "off" || v == "0" {
				ord.MuteWindowsSecSystray = true
			} else {
				ord.MuteWindowsSecSystray = false
			}
		case "watch":
			if v == "" || v == "none" || v == "off" {
				ord.AutoStandDownProcesses = nil
			} else {
				ord.AutoStandDownProcesses = strings.Split(v, ",")
			}
		default:
			fmt.Fprintf(os.Stderr, "Unknown setting %q\n", k)
			os.Exit(1)
		}
	}

	res, _ := gov.UpdateOrders(ord)
	for _, a := range res.Applied {
		fmt.Printf("  [✓] %s\n", a)
	}
	for _, w := range res.Warnings {
		fmt.Printf("  [!] %s\n", w)
	}
	runStatus(nil)
}

func runPause(args []string) {
	mins := 30
	if len(args) > 0 {
		if m, err := strconv.Atoi(args[0]); err == nil && m > 0 {
			mins = m
		}
	}
	gov := sheriff.NewGovernor()
	res := gov.StartStandDown(time.Duration(mins)*time.Minute, fmt.Sprintf("CLI %dm Pause", mins))
	fmt.Printf("Protection paused for %d minutes.\n", mins)
	for _, w := range res.Warnings {
		fmt.Printf("  [!] %s\n", w)
	}
}

func runResume() {
	gov := sheriff.NewGovernor()
	res := gov.ResumeFromStandDown()
	fmt.Println("Protection resumed.")
	for _, w := range res.Warnings {
		fmt.Printf("  [!] %s\n", w)
	}
}

func runScan() {
	fmt.Println("Running on-demand Quick Scan via Defender MpCmdRun.exe...")
	out, err := defender.RunQuickScan()
	if out != "" {
		fmt.Println(out)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Quick scan error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Quick Scan finished cleanly.")
}

func runUpdate() {
	fmt.Println("Updating Defender virus definitions via MpCmdRun.exe...")
	out, err := defender.UpdateSignatures()
	if out != "" {
		fmt.Println(out)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Signature update error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Definitions updated.")
}

func runService(args []string) {
	sub := "status"
	if len(args) > 0 {
		sub = strings.ToLower(args[0])
	}
	switch sub {
	case "run":
		if err := sheriff.RunWindowsService(); err != nil {
			fmt.Fprintf(os.Stderr, "Service dispatcher error: %v\n", err)
			os.Exit(1)
		}
	case "install":
		msg, err := sheriff.InstallService()
		fmt.Println(msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "uninstall", "remove":
		msg, err := sheriff.UninstallService()
		fmt.Println(msg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "Usage: shieldsheriff service <install|uninstall|run>")
	}
}

func runVersion(args []string) {
	for _, a := range args {
		if a == "--json" || a == "-j" {
			out, _ := json.MarshalIndent(version.Info(), "", "  ")
			fmt.Println(string(out))
			return
		}
	}
	fmt.Println(version.Summary())
}

func printUsage() {
	fmt.Printf("ShieldSheriff v%s (%s) - Simple, Nag-Free Control for Windows Defender\n\n", version.Version, version.Codename)
	fmt.Println(`Usage:
  shieldsheriff                         Inspect live Defender status (read-only) and exit
  shieldsheriff ui [--elevate]          Launch Dashboard UI (Read-Only window without tray unless --elevate)
  shieldsheriff tray [--elevate]        Launch persistent System Tray (requires elevation / --elevate)
  shieldsheriff status [--json]         Inspect live Defender status, Tamper Protection & Drift
  shieldsheriff apply [--preset <id>]   Apply configuration (use --elevate for UAC prompt)
  shieldsheriff set <k>=<v> ...         Configure individual settings
  shieldsheriff pause [minutes]         Temporarily pause Real-Time Protection
  shieldsheriff resume                  Resume Real-Time Protection from pause
  shieldsheriff scan                    Run on-demand Quick Scan via MpCmdRun.exe
  shieldsheriff update                  Update Defender definitions via MpCmdRun.exe
  shieldsheriff service <install|uninstall>  Manage 24/7 SYSTEM background enforcement service
  shieldsheriff version [--json]        Print CalVer release & Windows Defender platform metadata`)
	fmt.Println(`
Presets (--preset):
  cloud-local         Local + Cloud Protection ON, Sample Upload OFF, All Nags Silenced
  local-protection    Real-Time ON, Cloud OFF, Sample Submission OFF, All Nags Silenced
  workstation         Fast Builds (Behavior/Script hooks OFF, Auto-Pause on cargo/msbuild)
  on-demand           Real-Time OFF permanently (no 24h reset), Manual Scans ON, Nags Silenced

Granular Setting Keys (shieldsheriff set ...):
  realtime=on|off     behavior=on|off     ioav=on|off         script=on|off
  cloud=off|basic|advanced                samples=never|prompt|safe|all
  nags=off|on         systray=mute|show   network=off|block|audit
  watch=cargo.exe,msbuild.exe`)
}
