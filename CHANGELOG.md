# Changelog & Windows Defender Evolution Log

All notable changes to **ShieldSheriff** are documented in this file.

## Why CalVer (`YYYY.0M.MICRO`)?

Unlike a library with a purely abstract API contract (where SemVer `MAJOR.MINOR.PATCH` shines), **ShieldSheriff** governs an operating system subsystem—**Microsoft Defender Antivirus** (`MsMpEng.exe`, `WdFilter.sys`, `MpCmdRun.exe`) and **Windows Security Center** (`SecurityHealthService.exe`, `SecurityHealthSystray.exe`)—whose behavior shifts on Microsoft's monthly **Patch Tuesday** and **Windows 11 cumulative update** schedule:

1. **Time-Bound OS Behavior:** Microsoft regularly alters how `TamperProtection` bitmasks (`0x1`/`0x5` vs `0x0`/`0x4`), Group Policy registry keys (`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`), WMI (`ROOT\Microsoft\Windows\Defender:MSFT_MpPreference`), and `SecurityHealthService` toast notifications behave across monthly platform updates (`4.18.YYMM0.x`).
2. **Instant Compatibility Clarity:** A CalVer version like `2026.11.1` immediately tells users which Windows 11 cumulative update wave and Defender platform era the binary has been tested and hardened against.
3. **Format:** `YYYY.0M.MICRO`
   - `YYYY` — Four-digit release year (`2024`–`2026`)
   - `0M` — Zero-padded release month (`01`–`12`), aligned with Windows cumulative update waves
   - `MICRO` — Sequential release counter within that month (`1`, `2`, ...) for feature drops or rapid Patch Tuesday hotfixes

Machine-readable release and platform compatibility metadata is also maintained in [`VERSION.json`](VERSION.json) and exposed via `shiesh.exe version --json`.

---

## [2026.11.5] (2026-11-16)

* **Windows Baseline:** Windows 11 24H2 / 25H2 (`26100.2314+`)
* **Defender Platform Baseline:** `4.18.26100.5`

### Added
- **About Modal (`internal/ui/dashboard.html`):** Made the top-left **ShieldSheriff** brand and version clickable to open an About modal with developer attribution, MIT license note, and GitHub link.

### Changed
- **Streamlined System Tray Menu (`internal/tray/systray.go`):** Promoted preset options (`Quiet Guardian`, `Developer Workstation`, `On-Demand Only`, `Full Shield`) to top-level tray menu items and removed the `Protection Engines`, `Silence Security Nags`, and `Hide Windows Security Tray Icon` entries.

### Fixed
- **Consistent First-Run State in Settings (`internal/sheriff/governor.go`, `internal/ui/dashboard.html`):** Set `EnforceLoop` to `false` during initial unconfigured first-run state, added a `Not Configured` indicator in the Settings card, disabled the drift interval selector when Auto-Heal is off, and pre-populated the first-run consent modal from staged Settings values.

---

## [2026.11.4] (2026-11-16)

* **Windows Baseline:** Windows 11 24H2 / 25H2 (`26100.2314+`)
* **Defender Platform Baseline:** `4.18.26100.5`

### Added
- **Native WebView2 Window & Windows 11 Theme Sync (`internal/ui`):** Replaced `msedge.exe --app` with a pure-Go `go-webview2` host featuring Windows 11 Mica backdrop, rounded corners, matching caption color, live Dark/Light mode + DWM accent sync, and system UI font detection (`SPI_GETNONCLIENTMETRICS`).
- **First-Run Staging & Consent:** Launches cleanly without modifying Defender or hiding the Windows Security tray icon until the user stages changes, clicks **Apply Now**, and confirms startup, Auto-Heal, and update-check preferences.
- **Passive Mode (`internal/defender/enforce.go`, `internal/sheriff/governor.go`):** Added `RevertPolicies()` and `EnterPassiveMode()` to stop enforcement and restore pre-ShieldSheriff settings.
- **Logon Startup & Update Checker (`internal/sheriff/startup.go`, `internal/sheriff/update.go`):** Added elevated Task Scheduler logon registration (`ShieldSheriff Tray`) and GitHub Releases update checks on startup and from **Settings**.
- **Dedicated Logs View & Local Build Script (`build.ps1`):** Moved **Telemetry & Audit Log** into its own **Logs** section and codified `go build -trimpath -ldflags="-s -w" -o bin\shiesh.exe ./cmd/shieldsheriff` in `build.ps1`.

### Changed
- **Binary & Config Naming:** Renamed the output binary from `shieldsheriff.exe` to `shiesh.exe` and standardized the config file to `config.json`.
- **Three-State System Tray & Direct Copy (`internal/tray`):** Updated tray icons to reflect **Preset Mode** (matching each preset's shield icon), **Pause Mode** (amber shield with `||`), and **Passive Mode** (hollow slate shield outline), and replaced analogy-heavy menu/UI labels with direct terminology.
- **Simplified App Logo (`site/logo.svg`, `internal/ui`, `internal/tray`):** Updated the logo to a single-color tilted hat with negative-space crease lines inset in a dark shield.
- **Auto-Heal Interval & UAC Startup (`cmd/shieldsheriff/main.go`, `internal/sheriff/governor.go`):** Set Auto-Heal default to 15s (configurable 10s–15m), healed transient drift in `Snapshot()` when Auto-Heal is active, auto-requested UAC on interactive launch with Read-Only fallback, and closed the UI window cleanly on tray exit.
- **Static Site & Docs (`site/`, `README.md`):** Updated `site/` with a live app screenshot (`site/preview.png`) and Fluent charcoal palette, and aligned `README.md` with the current UX.

### Fixed
- **Defender Policy Precedence (`internal/defender/inspect.go`):** Fixed `Inspect()` to prioritize Group Policy keys (`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\...`) over local preference keys when Tamper Protection is off, preventing false drift reports on `On-Demand Only`.

---

## [2026.11.3] (2026-11-15)

* **Windows Baseline:** Windows 11 24H2 / 25H2 (`26100.2314+`)
* **Defender Platform Baseline:** `4.18.26100.5`

### Added
- **Portable GitHub Release & Winget Workflow (`.github/workflows/release.yml`, `packaging/winget/`):** Automated `amd64`/`arm64` portable `.zip` releases with `SHA256SUMS.txt` and Winget manifest rendering.

### Changed
- **Background Terminal Suppression & Clean Shutdown (`cmd/shieldsheriff/console_windows.go`, `internal/tray/systray.go`):** Suppressed owned console windows on GUI/tray launch, improved tray status indicators, and ensured server and governor shut down cleanly when exiting the tray.

---

## [2026.11.2] (2026-11-15)

* **Windows Baseline:** Windows 11 24H2 / 25H2 (`26100.2314+`)
* **Defender Platform Baseline:** `4.18.26100.5`

### Changed
- **Compact Tabbed Command Center UI (`internal/ui/dashboard.html`, `internal/ui/server.go`):** Redesigned the Command Center into a compact two-tab layout (`Sheriff Presets & Controls` and `Operations, Stand-Down & Audit`) sized cleanly to `840x750` in an isolated Edge app profile (`--user-data-dir`) with zero horizontal overflow or hover jitter.
- **Inline SVG Sheriff Preset Cards & Hover Diff Preview:** Added custom vector Sheriff illustrations ordered left-to-right (`On-Demand Deputy` → `Developer Workstation` → `Quiet Guardian` → `Full Shield`), paired with live hover-diff preview highlights and granular override controls.

### Added
- **Single-Instance Process & Window Locking (`cmd/shieldsheriff/instance.go`, `internal/ui/window.go`):** Enforced single interactive instance locking via a named Windows mutex (`Local\ShieldSheriffCommandCenterInstance`), `/api/focus` handoff, `--replace` elevation handoff, and Win32 `EnumWindows` / `SetForegroundWindow` deduplication in `OpenWindow()`.

---

## [2026.11.1] — "Peacekeeper" (2026-11-15)

* **Windows Baseline:** Windows 11 24H2 / 25H2 (`26100.2314+`)
* **Defender Platform Baseline:** `4.18.26100.5`

### Added
- **Version Metadata & CLI (`internal/version`, `VERSION.json`):** Added `shieldsheriff version [--json]` and embedded CalVer release & Defender platform compatibility metadata in `status --json` and `/api/state`.
- **Interactive Comparison Site (`site/`):** Added static documentation and interactive Standing Orders & scenario comparison site (`site/index.html`, `site/styles.css`, `site/app.js`) comparing ShieldSheriff against Defender Control, ConfigureDefender, and DefenderUI.

### Changed
- **November 2026 Patch Tuesday Verification:** Verified policy lock persistence and `DisableEnhancedNotifications` behavior against the November 2026 Defender platform (`4.18.26100.5`).
- **Command Center Header Badge:** Added live CalVer release badge (`#versionBadge`) to the embedded Command Center header.

---

## [2026.08.1] — "Command Center" (2026-08-23)

* **Windows Baseline:** Windows 11 24H2 / 25H2 Preview (`26100.1457+`)
* **Defender Platform Baseline:** `4.18.26070.3`

### Added
- **Embedded Localhost Command Center (`internal/ui`):** Built a zero-dependency localhost (`127.0.0.1:38419`) HTTP API and dark-mode single-page dashboard (`dashboard.html`) embedded directly into the Go binary via `//go:embed`.
- **Chromeless App-Mode Window Launcher:** Automatically launches Microsoft Edge in `--app` mode (`1160x820`) for a native desktop control panel feel without bundling a 150 MB Electron/WebView2 runtime, with graceful fallback to the default browser.
- **One-Time Tamper Protection Handoff Callout:** Added live UI detection when `WdFilter.sys` Tamper Protection is active (`0x1` / `0x5`), providing a one-click `windowsdefender://threatsettings` shortcut and explanation.
- **Live Audit Log Viewer:** Real-time ring buffer view of `INIT`, `ENFORCE`, `DRIFT`, and `STANDDOWN` events in the Command Center UI.

---

## [2026.04.1] — "Gold Star" (2026-04-26)

* **Windows Baseline:** Windows 11 24H2 (`26100.712`)
* **Defender Platform Baseline:** `4.18.26030.2`

### Added
- **Procedural Win32 HICON Renderer (`internal/tray/icon.go`):** Pure-Go 32x32 32-bit ARGB DIB section icon generator with 2x2 supersampling, metallic bevel shading, and ball finials—rendering three distinct 6-pointed Sheriff Star states with zero external `.ico` asset files:
  - **Gold Star:** Full compliance ("Keeping the Peace")
  - **Cyan Ice Star:** Deputy Standing Down (timed or compiler-triggered pause)
  - **Amber Star:** Configuration drift detected or running unprivileged
- **Native Win32 System Tray (`internal/tray/systray.go`):** Implemented `Shell_NotifyIconW` tray loop and `TrackPopupMenu` context menus for 1-click preset switching, granular engine toggles, timed stand-downs (15m / 30m / 1h / 4h), and balloon notifications.

---

## [2025.12.1] — "Night Watch" (2025-12-21)

* **Windows Baseline:** Windows 11 24H2 (`26100.2605`)
* **Defender Platform Baseline:** `4.18.25110.6`

### Context: Late-2025 Windows Update Policy Resets
Following the late-2025 Windows 11 cumulative updates and Defender platform `4.18.25110.x` rollout, monthly servicing passes began periodically clearing `Real-Time Protection` and `Spynet` policy overrides or re-enabling `SecurityHealth` startup entries after reboot.

### Added
- **Native Windows Service Dispatcher (`internal/sheriff/service.go`):** Implemented raw Win32 `StartServiceCtrlDispatcherW` and `RegisterServiceCtrlHandlerExW` callbacks so `shieldsheriff.exe service install` registers a lightweight 24/7 `SYSTEM` service (`ShieldSheriff Defender Governor`) across reboots.
- **5-Second Drift Auto-Healer (`internal/sheriff/governor.go`):** Added continuous compliance evaluation (`EvaluateCompliance`) that detects when a Windows Update or signature refresh flips any governed setting and automatically re-applies Standing Orders within 5 seconds.

---

## [2025.09.1] — "Stand-Down" (2025-09-21)

* **Windows Baseline:** Windows 11 24H2 (`26100.1742`)
* **Defender Platform Baseline:** `4.18.25080.5`

### Context: Dev Drive & Compiler I/O Bottlenecks on 24H2
In summer/fall 2025, Defender platform `4.18.25080.x` expanded synchronous `WdFilter.sys` minifilter and AMSI inspection on newly linked PE binaries and incremental build directories, causing severe build slowdowns for Rust (`cargo.exe`, `rustc.exe`), C++/MSBuild (`msbuild.exe`, `link.exe`), and Go toolchains.

### Added
- **Process-Aware Auto Stand-Down (`FindRunningWatchedProcess`):** Uses native Win32 `CreateToolhelp32Snapshot` / `Process32FirstW` / `Process32NextW` to poll active processes with near-zero CPU overhead and automatically pause Real-Time Protection while watched compilers run, restoring Standing Orders immediately on exit.
- **Timed Manual Stand-Down (`shieldsheriff standdown [minutes]`):** Pause Real-Time Protection for a fixed window without relying on Windows Security's arbitrary 24-hour reset timer.
- **Built-In Presets (`internal/defender/state.go`):** Standardized four signature presets: `quiet-guardian`, `dev-workstation`, `on-demand-only`, and `full-shield-no-nag`.

---

## [2025.06.2] — "DCOM Bridge Hotfix" (2025-06-15)

* **Windows Baseline:** Windows 11 24H2 (`26100.863`)
* **Defender Platform Baseline:** `4.18.25050.5`

### Fixed
- **DCOM `CimSession` Transport (`internal/defender/enforce.go`):** Replaced default PowerShell `Set-MpPreference` invocation with an explicit `New-CimSessionOption -Protocol Dcom` session. Hardened workstations and privacy-tuned Windows 11 installs often disable the `WinRM` / `WSMan` service, causing default CIM cmdlets to fail even when elevated.
- **Tamper Protection `0x4` / `0x5` Bitmask Parsing (`internal/defender/inspect.go`):** Updated `TamperProtection` registry inspection under `HKLM\SOFTWARE\Microsoft\Windows Defender\Features` to test bit 0 (`(tp & 0x1) != 0`) after Defender platform `4.18.25050` began writing `0x4` (disabled) and `0x5` (enabled) instead of `0x0` and `0x1`.

---

## [2025.06.1] — "Direct Sync" (2025-06-08)

* **Windows Baseline:** Windows 11 24H2 (`26100.863`)
* **Defender Platform Baseline:** `4.18.25050.5`

### Context: Defender Platform `4.18.25050+` In-Memory Preference Caching
Starting in May/June 2025 (`4.18.25050.x`), `MsMpEng.exe` stopped immediately hot-reloading changes written solely to `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` until either a service restart (blocked for non-PPL processes) or a WMI `MSFT_MpPreference` commit occurred.

### Added
- **Dual Policy + WMI Enforcement (`syncWMIPreferences`):** `defender.Enforce` now writes both persistent Group Policy locks (`HKLM\SOFTWARE\Policies\...`) AND live engine keys (`HKLM\SOFTWARE\Microsoft\Windows Defender\...`), then synchronizes `MSFT_MpPreference` via WMI so `MsMpEng.exe` applies toggles immediately without rebooting.
- **Never Set `DisableAntiSpyware=1`:** Explicitly keeps `DisableAntiSpyware=0` and `DisableAntiVirus=0` (deprecated and ignored by modern Defender platforms) so `WinDefend` stays alive for `MpCmdRun.exe` manual scans and definition updates even in `on-demand-only` mode.

---

## [2025.02.1] — "Silent Star" (2025-02-16)

* **Windows Baseline:** Windows 11 24H2 (`26100.3194`)
* **Defender Platform Baseline:** `4.18.25010.11`

### Context: Windows 11 24H2 "Enhanced Notifications" Nag Wave
In early 2025, Windows 11 24H2 updates expanded `SecurityHealthService.exe` and `SecurityHealthSystray.exe` to fire recurring "Action Needed" toast notifications and yellow exclamation badges whenever **Cloud-delivered protection** (`SpyNetReporting=0`), **Automatic sample submission** (`SubmitSamplesConsent=2`), or **Tamper protection** was intentionally turned off by the user—even when local Real-Time Protection remained enabled.

### Added
- **Multi-Layer Nag Suppression (`internal/defender/enforce.go`):**
  - Sets `DisableNotifications=1` and `DisableEnhancedNotifications=1` under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications`.
  - Sets `Notification_Suppress=1` under both policy and live `UX Configuration` keys.
  - Disables `Windows.SystemToast.SecurityAndMaintenance` user toast channel under `HKCU`.
- **Reversible Systray Muting:** Added optional `MuteWindowsSecSystray` order that sets `HideSystray=1` and backs up `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth` to `HKLM\SOFTWARE\ShieldSheriff\Backup\SecurityHealthRun` before removing the autorun entry, restoring it cleanly whenever unmuted.

---

## [2024.12.1] — "First Badge" (2024-12-15)

* **Windows Baseline:** Windows 11 23H2 / 24H2 (`26100.2314`)
* **Defender Platform Baseline:** `4.18.24090.11`

### Context: Why ShieldSheriff Was Started
Existing third-party tools fell into two extremes:
1. **Kill-switch tools** (like Defender Control) used `TrustedInstaller` hacks or fake Windows Security Center (`WSC`) antivirus registrations (such as the `defnot` technique), which forced `MsMpEng.exe` into Passive Mode—killing Real-Time Protection completely, breaking manual scans, and triggering `HackTool:Win32` detections.
2. **Hardening GUIs** (like ConfigureDefender / DefenderUI) focused on cranking cloud telemetry and ASR rules *up*, leaving privacy-conscious users with constant Windows Security nag popups if they turned Cloud Lookup or Automatic Sample Submission off.

### Added
- **Core Native Win32 Inspector (`internal/defender/inspect.go`):** Zero-dependency `advapi32.dll` (`RegOpenKeyExW` / `RegQueryValueExW`) inspector reading live Defender engine, Spynet/MAPS, Network Protection, and Tamper Protection state with or without Administrator privileges.
- **UAC Self-Elevation (`internal/defender/elevation.go`):** Token elevation inspection (`GetTokenInformation`) and `ShellExecuteW("runas")` self-elevation for `shieldsheriff elect --elevate`.
- **Standing Orders & CLI (`cmd/shieldsheriff`, `internal/sheriff/config.go`):** Persistent JSON configuration (`%ProgramData%\ShieldSheriff\standing_orders.json`) and `status`, `elect`, `order`, `scan`, and `update` CLI commands wrapping `MpCmdRun.exe`.
