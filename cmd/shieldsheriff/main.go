//go:build windows

//go:generate go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --out rsrc --arch amd64,arm64

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
		fmt.Println("  Launch UI / Tray : shiesh ui [--elevate]  |  shiesh tray [--elevate]")
		fmt.Println("  All Commands     : shiesh help")
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
		runResume(args[1:])
	case "passive":
		runPassive(args[1:])
	case "scan":
		runScan()
	case "update":
		runUpdate()
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

// stripElevateFlags removes --elevate / -e from args and reports whether elevation was requested.
func stripElevateFlags(args []string) ([]string, bool) {
	want := false
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.EqualFold(a, "--elevate") || strings.EqualFold(a, "-e") {
			want = true
			continue
		}
		out = append(out, a)
	}
	return out, want
}

func runInteractive(openWindowOnStart bool, replaceExisting bool, wantElevate bool) {
	suppressOwnedConsoleWindow()

	const instanceMutexName = `Local\ShieldSheriffInstance`
	const preferredPort = 38419

	var (
		release        func()
		alreadyRunning bool
		err            error
	)
	deadline := time.Now()
	if replaceExisting {
		deadline = deadline.Add(5 * time.Second)
	}
	for {
		release, alreadyRunning, err = acquireSingleInstance(instanceMutexName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Single-instance mutex error: %v\n", err)
			os.Exit(1)
		}
		if !alreadyRunning || !replaceExisting || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if alreadyRunning {
		if openWindowOnStart {
			_ = focusExistingInstance()
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
	st, cfg, _, _ := gov.Snapshot()
	if !st.IsElevated {
		if !openWindowOnStart {
			fmt.Fprintln(os.Stderr, "System Tray mode requires Administrator privileges. Run `shiesh tray --elevate` (or launch from an elevated shell).")
			os.Exit(1)
		}
		runReadOnlyUI(gov, preferredPort)
		return
	}

	if cfg.Mode == defender.ModeActive && !st.TamperProtectionActive {
		gov.EnforceNow()
	}
	gov.StartLoop()
	defer gov.StopLoop()

	srv, err := ui.StartServer(gov, preferredPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start Dashboard UI server: %v\n", err)
		os.Exit(1)
	}
	srv.PublishRuntimeEndpoints()

	fmt.Printf("ShieldSheriff Dashboard running at %s\n", srv.URL())
	if openWindowOnStart {
		srv.OpenWindow()
	}

	appTray := tray.NewAppTray(gov, func() {
		srv.OpenWindow()
	})
	srv.SetOnShutdown(appTray.Quit)

	if cfg.Mode == defender.ModeActive && cfg.Preferences.CheckUpdatesOnStart {
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
	srv.PublishRuntimeEndpoints()

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
	st, cfg, _, cfgPath := gov.Snapshot()

	for _, a := range args {
		if a == "--json" || a == "-j" {
			out, _ := json.MarshalIndent(map[string]any{
				"version":     version.Info(),
				"status":      st,
				"config":      cfg,
				"configError": gov.ConfigError(),
				"configPath":  cfgPath,
			}, "", "  ")
			fmt.Println(string(out))
			return
		}
	}

	pol := cfg.Policy
	fmt.Println("================================================================")
	fmt.Printf("  SHIELDSHERIFF v%s (%s) - DEFENDER STATUS & CONFIGURATION\n", version.Version, version.Codename)
	fmt.Println("================================================================")
	fmt.Printf("  Privilege Level     : %s\n", map[bool]string{true: "Elevated (Administrator)", false: "Standard User (Read-Only)"}[st.IsElevated])
	fmt.Printf("  Mode / Preset       : %s / %s (%s)\n", cfg.Mode, defender.PresetDisplayName(pol.PresetID), cfgPath)
	if cfgErr := gov.ConfigError(); cfgErr != "" {
		fmt.Printf("  Config Error        : ! %s\n", cfgErr)
	}
	fmt.Printf("  Defender Service    : %s (Platform %s | Signatures %s)\n",
		map[bool]string{true: "RUNNING", false: "STOPPED"}[st.ServiceRunning],
		st.PlatformVersion, st.SignatureVersion)
	fmt.Printf("  Tamper Protection   : %s (raw=0x%x)\n",
		map[bool]string{true: "ON  [Blocks policy writes - toggle OFF once in Windows Security]", false: "OFF [Ready for ShieldSheriff]"}[st.TamperProtectionActive],
		st.TamperProtectionRaw)
	if cfg.Pause.Active {
		fmt.Printf("  Pause Status        : ACTIVE (%s)\n", cfg.Pause.Reason)
	}
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("  SETTING                         LIVE STATE          CONFIGURED")
	fmt.Println("----------------------------------------------------------------")
	printRow := func(name, live, configured string) {
		fmt.Printf("  %-30s  %-18s  %s\n", name, live, configured)
	}
	onOff := func(b bool) string {
		if b {
			return "ON"
		}
		return "OFF"
	}
	printRow("Real-Time Protection", onOff(st.RealtimeProtection), onOff(pol.RealtimeProtection))
	printRow("Behavior Monitoring", onOff(st.BehaviorMonitoring), onOff(pol.BehaviorMonitoring))
	printRow("Downloaded Files (IOAV)", onOff(st.IOAVProtection), onOff(pol.IOAVProtection))
	printRow("Script Scanning (AMSI)", onOff(st.ScriptScanning), onOff(pol.ScriptScanning))
	printRow("Network Protection", fmt.Sprintf("Mode %d", st.NetworkProtection), fmt.Sprintf("Mode %d", pol.NetworkProtection))
	printRow("Cloud Protection (MAPS)", fmt.Sprintf("Mode %d (%s)", st.CloudProtection, map[bool]string{true: "OFF", false: "ON"}[st.CloudProtection == 0]), fmt.Sprintf("Mode %d", pol.CloudProtection))
	printRow("Sample Submission", fmt.Sprintf("Mode %d (%s)", st.SampleSubmission, map[bool]string{true: "Never/OFF", false: "Active"}[st.SampleSubmission == 2]), fmt.Sprintf("Mode %d", pol.SampleSubmission))
	printRow("Security Center Nags", map[bool]string{true: "SILENCED", false: "ACTIVE (Nagging)"}[st.NagsSuppressed], map[bool]string{true: "SILENCED", false: "Allow"}[pol.SuppressAllNags])
	printRow("Windows Security Tray Icon", map[bool]string{true: "MUTED", false: "VISIBLE"}[st.SecurityTrayIconMuted], map[bool]string{true: "MUTED", false: "VISIBLE"}[pol.MuteWindowsSecSystray])
	fmt.Println("----------------------------------------------------------------")
	if cfg.Mode != defender.ModeActive {
		fmt.Printf("  COMPLIANCE: NOT ENFORCING (%s)\n", cfg.Mode)
	} else if st.InCompliance {
		fmt.Println("  COMPLIANCE: IN COMPLIANCE")
	} else {
		fmt.Printf("  COMPLIANCE: ! %d DRIFT ITEM(S) DETECTED:\n", len(st.DriftItems))
		for _, d := range st.DriftItems {
			fmt.Printf("    - %s\n", d)
		}
		if !st.IsElevated {
			fmt.Println("\n  Tip: Run `shiesh apply --elevate` to apply configuration as Administrator.")
		}
	}
	fmt.Println("================================================================")
}

func runApply(args []string) {
	cleanArgs, wantElevate := stripElevateFlags(args)

	var presetID string
	for i := 0; i < len(cleanArgs); i++ {
		a := cleanArgs[i]
		if a == "--preset" || a == "-p" {
			if i+1 >= len(cleanArgs) {
				fmt.Fprintln(os.Stderr, "Missing value for --preset")
				os.Exit(1)
			}
			i++
			presetID = strings.ToLower(strings.TrimSpace(cleanArgs[i]))
			if _, ok := defender.FindPreset(presetID); !ok {
				fmt.Fprintf(os.Stderr, "Unknown preset %q. Available: %s\n", presetID, strings.Join(defender.PresetIDs(), ", "))
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Unknown argument %q for apply\n", a)
			os.Exit(1)
		}
	}

	if !defender.IsProcessElevated() && wantElevate {
		forward := append([]string{"apply"}, cleanArgs...)
		fmt.Println("Requesting Administrator privileges via UAC to apply configuration...")
		if err := defender.RelaunchElevated(forward); err != nil {
			fmt.Fprintf(os.Stderr, "Elevation failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	gov := sheriff.NewGovernor()
	_, cfg, _, _ := gov.Snapshot()

	targetPolicy := cfg.Policy.Clone()
	targetPrefs := cfg.Preferences
	if presetID != "" {
		p, _ := defender.FindPreset(presetID)
		targetPolicy = p.Policy
		if cfg.Mode == defender.ModeUnconfigured {
			targetPrefs.AutoHeal = true
		}
	} else if cfg.Mode == defender.ModeUnconfigured {
		// Bare `shiesh apply` on an unconfigured machine applies the default Local Protection preset.
		targetPolicy = defender.DefaultPolicy()
		targetPrefs.AutoHeal = true
	}

	if remote, handled := sendToRunningGovernor("/api/config", map[string]any{
		"mode":        defender.ModeActive,
		"policy":      targetPolicy,
		"preferences": targetPrefs,
	}); handled {
		printEnforceResult(remote.Result)
		if !remote.OK && len(remote.Result.Warnings) == 0 {
			fmt.Fprintf(os.Stderr, "  [!] %s\n", remote.Message)
		}
		runStatus(nil)
		return
	}

	var (
		res defender.EnforceResult
		err error
	)
	if presetID != "" {
		res, err = gov.ApplyPreset(presetID)
	} else {
		res, err = gov.UpdateConfig(defender.ModeActive, targetPolicy, targetPrefs)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Note saving settings: %v\n", err)
	}
	printEnforceResult(res)
	runStatus(nil)
}

func parseStrictBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1", "yes", "enabled", "enable":
		return true, nil
	case "off", "false", "0", "no", "disabled", "disable":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q (expected on|off|true|false|1|0)", v)
	}
}

func applySetArgs(pol defender.Policy, args []string) (defender.Policy, error) {
	if len(args) == 0 {
		return pol, fmt.Errorf("no key=value settings provided")
	}
	pol = pol.Clone()
	pol.PresetID = "custom"

	for _, arg := range args {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			return pol, fmt.Errorf("invalid key=value pair: %q", arg)
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		v := strings.ToLower(strings.TrimSpace(parts[1]))

		switch k {
		case "realtime", "rtp":
			b, err := parseStrictBool(v)
			if err != nil {
				return pol, fmt.Errorf("%s: %w", k, err)
			}
			pol.RealtimeProtection = b
		case "behavior", "bm":
			b, err := parseStrictBool(v)
			if err != nil {
				return pol, fmt.Errorf("%s: %w", k, err)
			}
			pol.BehaviorMonitoring = b
		case "ioav", "downloads":
			b, err := parseStrictBool(v)
			if err != nil {
				return pol, fmt.Errorf("%s: %w", k, err)
			}
			pol.IOAVProtection = b
		case "script", "amsi":
			b, err := parseStrictBool(v)
			if err != nil {
				return pol, fmt.Errorf("%s: %w", k, err)
			}
			pol.ScriptScanning = b
		case "network", "net":
			switch v {
			case "off", "0", "false":
				pol.NetworkProtection = 0
			case "on", "block", "1", "true":
				pol.NetworkProtection = 1
			case "audit", "2":
				pol.NetworkProtection = 2
			default:
				return pol, fmt.Errorf("invalid network value %q (expected off|block|audit)", v)
			}
		case "cloud", "maps", "spynet":
			switch v {
			case "off", "0", "false":
				pol.CloudProtection = 0
			case "basic", "1":
				pol.CloudProtection = 1
			case "advanced", "on", "2", "true":
				pol.CloudProtection = 2
			default:
				return pol, fmt.Errorf("invalid cloud value %q (expected off|basic|advanced)", v)
			}
		case "samples", "submit":
			switch v {
			case "off", "never", "2", "false":
				pol.SampleSubmission = 2
			case "prompt", "0":
				pol.SampleSubmission = 0
			case "safe", "1", "on", "true":
				pol.SampleSubmission = 1
			case "all", "3":
				pol.SampleSubmission = 3
			default:
				return pol, fmt.Errorf("invalid samples value %q (expected never|prompt|safe|all)", v)
			}
		case "nags", "notifications":
			switch v {
			case "off", "silence", "mute", "suppressed", "0", "false":
				pol.SuppressAllNags = true
				pol.SuppressEnhancedNags = true
			case "on", "allow", "show", "1", "true":
				pol.SuppressAllNags = false
				pol.SuppressEnhancedNags = false
			default:
				return pol, fmt.Errorf("invalid nags value %q (expected off|on)", v)
			}
		case "systray", "tray-nag":
			switch v {
			case "mute", "hide", "off", "0":
				pol.MuteWindowsSecSystray = true
			case "show", "visible", "on", "1":
				pol.MuteWindowsSecSystray = false
			default:
				return pol, fmt.Errorf("invalid systray value %q (expected mute|show)", v)
			}
		case "watch":
			if v == "" || v == "none" || v == "off" {
				pol.AutoPauseProcesses = []string{}
			} else {
				raw := strings.Split(parts[1], ",")
				list := make([]string, 0, len(raw))
				for _, item := range raw {
					if trimmed := strings.TrimSpace(item); trimmed != "" {
						list = append(list, trimmed)
					}
				}
				pol.AutoPauseProcesses = list
			}
		default:
			return pol, fmt.Errorf("unknown setting %q", k)
		}
	}
	return pol, pol.Validate()
}

func runSet(args []string) {
	cleanArgs, wantElevate := stripElevateFlags(args)
	if len(cleanArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: shiesh set <key>=<value> [key=value ...] [--elevate]")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  shiesh set realtime=on cloud=off samples=never nags=off")
		fmt.Fprintln(os.Stderr, "  shiesh set behavior=off script=off systray=mute")
		os.Exit(1)
	}

	// Validate inputs before requesting elevation so typos fail fast without a UAC prompt.
	gov := sheriff.NewGovernor()
	_, cfg, _, _ := gov.Snapshot()
	updatedPolicy, err := applySetArgs(cfg.Policy, cleanArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !defender.IsProcessElevated() && wantElevate {
		forward := append([]string{"set"}, cleanArgs...)
		fmt.Println("Requesting Administrator privileges via UAC to apply settings...")
		if err := defender.RelaunchElevated(forward); err != nil {
			fmt.Fprintf(os.Stderr, "Elevation failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	prefs := cfg.Preferences
	if cfg.Mode == defender.ModeUnconfigured {
		prefs.AutoHeal = true
	}

	if remote, handled := sendToRunningGovernor("/api/config", map[string]any{
		"mode":        defender.ModeActive,
		"policy":      updatedPolicy,
		"preferences": prefs,
	}); handled {
		printEnforceResult(remote.Result)
		if !remote.OK && len(remote.Result.Warnings) == 0 {
			fmt.Fprintf(os.Stderr, "  [!] %s\n", remote.Message)
		}
		runStatus(nil)
		return
	}

	res, saveErr := gov.UpdateConfig(defender.ModeActive, updatedPolicy, prefs)
	if saveErr != nil {
		fmt.Fprintf(os.Stderr, "Note saving settings: %v\n", saveErr)
	}
	printEnforceResult(res)
	runStatus(nil)
}

func runPause(args []string) {
	cleanArgs, wantElevate := stripElevateFlags(args)
	mins := 30
	if len(cleanArgs) > 1 {
		fmt.Fprintln(os.Stderr, "Usage: shiesh pause [minutes] [--elevate]")
		os.Exit(1)
	}
	if len(cleanArgs) == 1 {
		m, err := strconv.Atoi(cleanArgs[0])
		if err != nil || m <= 0 {
			fmt.Fprintf(os.Stderr, "Invalid pause duration %q (expected a positive number of minutes)\n", cleanArgs[0])
			os.Exit(1)
		}
		mins = m
	}

	if !defender.IsProcessElevated() && wantElevate {
		forward := append([]string{"pause"}, cleanArgs...)
		if err := defender.RelaunchElevated(forward); err != nil {
			fmt.Fprintf(os.Stderr, "Elevation failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	reason := fmt.Sprintf("CLI %dm Pause", mins)
	if remote, handled := sendToRunningGovernor("/api/pause", map[string]any{
		"minutes": mins,
		"reason":  reason,
	}); handled {
		fmt.Println(remote.Message)
		printWarnings(remote.Result.Warnings)
		if !remote.OK {
			os.Exit(1)
		}
		return
	}

	gov := sheriff.NewGovernor()
	res, err := gov.StartPause(time.Duration(mins)*time.Minute, reason)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pause failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Protection paused for %d minutes.\n", mins)
	printWarnings(res.Warnings)
	fmt.Println("  [!] Note: No ShieldSheriff tray instance is running to auto-resume when the timer expires.")
	fmt.Println("      Run `shiesh tray --elevate` for automatic resume, or `shiesh resume` when done.")
}

func runResume(args []string) {
	_, wantElevate := stripElevateFlags(args)
	if !defender.IsProcessElevated() && wantElevate {
		if err := defender.RelaunchElevated([]string{"resume"}); err != nil {
			fmt.Fprintf(os.Stderr, "Elevation failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if remote, handled := sendToRunningGovernor("/api/pause", map[string]any{"minutes": 0}); handled {
		fmt.Println(remote.Message)
		printWarnings(remote.Result.Warnings)
		if !remote.OK {
			os.Exit(1)
		}
		return
	}

	gov := sheriff.NewGovernor()
	res, err := gov.ResumePause()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Resume failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Protection resumed.")
	printWarnings(res.Warnings)
}

func runPassive(args []string) {
	_, wantElevate := stripElevateFlags(args)
	if !defender.IsProcessElevated() && wantElevate {
		if err := defender.RelaunchElevated([]string{"passive"}); err != nil {
			fmt.Fprintf(os.Stderr, "Elevation failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if remote, handled := sendToRunningGovernor("/api/passive", nil); handled {
		fmt.Println(remote.Message)
		printEnforceResult(remote.Result)
		if !remote.OK {
			os.Exit(1)
		}
		return
	}

	gov := sheriff.NewGovernor()
	res, err := gov.EnterPassiveMode()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Note saving passive state: %v\n", err)
	}
	printEnforceResult(res)
	if !res.Success {
		os.Exit(1)
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

func printEnforceResult(res defender.EnforceResult) {
	for _, a := range res.Applied {
		fmt.Printf("  [✓] %s\n", a)
	}
	printWarnings(res.Warnings)
}

func printWarnings(warnings []string) {
	for _, w := range warnings {
		fmt.Printf("  [!] %s\n", w)
	}
}

func printUsage() {
	fmt.Printf("ShieldSheriff v%s (%s) - Simple, Nag-Free Control for Windows Defender\n\n", version.Version, version.Codename)
	fmt.Println(`Usage:
  shiesh                         Inspect live Defender status (read-only) and exit
  shiesh ui [--elevate]          Launch Dashboard UI (Read-Only window without tray unless --elevate)
  shiesh tray [--elevate]        Launch persistent System Tray (requires elevation / --elevate)
  shiesh status [--json]         Inspect live Defender status, Tamper Protection & Drift
  shiesh apply [--preset <id>]   Apply configuration (use --elevate for UAC prompt)
  shiesh set <k>=<v> ...         Configure individual settings (use --elevate for UAC prompt)
  shiesh pause [minutes]         Temporarily pause Real-Time Protection
  shiesh resume                  Resume Real-Time Protection from pause
  shiesh passive [--elevate]     Stop enforcing and revert ShieldSheriff policy changes
  shiesh scan                    Run on-demand Quick Scan via MpCmdRun.exe
  shiesh update                  Update Defender definitions via MpCmdRun.exe
  shiesh version [--json]        Print CalVer release & Windows Defender platform metadata`)

	fmt.Println("\nPresets (--preset):")
	for _, p := range defender.BuiltinPresets() {
		fmt.Printf("  %-18s  %s\n", p.ID, p.Description)
	}

	fmt.Println(`
Granular Setting Keys (shiesh set ...):
  realtime=on|off     behavior=on|off     ioav=on|off         script=on|off
  cloud=off|basic|advanced                samples=never|prompt|safe|all
  nags=off|on         systray=mute|show   network=off|block|audit
  watch=cargo.exe,msbuild.exe`)
}
