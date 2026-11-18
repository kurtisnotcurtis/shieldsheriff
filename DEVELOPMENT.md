# ShieldSheriff Development & Architecture Guide

This document covers the repository layout, internal Windows 11 / Defender architecture, local build and test workflows, and release packaging for **ShieldSheriff**.

For end-user installation and usage instructions, see [README.md](README.md).

---

## Project Structure

```text
shieldsheriff/
├── cmd/shieldsheriff/
│   ├── main.go                     # CLI, System Tray, Dashboard UI & Windows Service entry point
│   ├── main_test.go                # CLI argument & interactive mode flag tests
│   ├── instance.go                 # Single-instance named mutex & Dashboard focus handoff
│   ├── console_windows.go          # Console window suppression for GUI/Tray launches
│   └── winres/                     # Windows application manifest & icon resource definitions
├── internal/
│   ├── defender/
│   │   ├── state.go                # StandingOrders, DeputyStatus, StandDownState, and Presets
│   │   ├── inspect.go              # Native Win32 Registry & filesystem inspector (works unprivileged & elevated)
│   │   ├── enforce.go              # Policy locks + live Engine keys + DCOM WMI (MSFT_MpPreference) sync
│   │   └── elevation.go            # Token elevation check + UAC self-elevation ("runas")
│   ├── sheriff/
│   │   ├── config.go               # Persistent config.json storage (%ProgramData%\ShieldSheriff)
│   │   ├── governor.go             # Drift auto-healer, Pause timer & Win32 Toolhelp32 process watcher
│   │   ├── startup.go              # Elevated logon Task Scheduler registration (`ShieldSheriff Tray`)
│   │   ├── update.go               # GitHub Releases update checker
│   │   └── service.go              # Native Windows Service (SCM) dispatcher & installer
│   ├── tray/
│   │   ├── icon.go                 # Procedural 32-bit ARGB preset, pause, passive & brand HICON renderer
│   │   └── systray.go              # Native Win32 Shell_NotifyIconW System Tray & popup menu
│   ├── ui/
│   │   ├── server.go               # Localhost (127.0.0.1) UI server & WebView2 native window host
│   │   ├── theme.go                # Windows 11 Dark/Light mode, DWM accent & system UI font reader
│   │   ├── window.go               # Windows 11 Mica/caption chrome, icon & HWND deduplication
│   │   ├── dashboard.html          # Windows 11 Settings-style dual-pane UI with staged Apply Now
│   │   └── assets.go               # Embedded UI assets
│   └── version/
│       ├── version.go              # CalVer (YYYY.0M.MICRO) release & Defender platform compatibility metadata
│       └── version_test.go         # Enforces version sync across VERSION.json, version.go, and CHANGELOG.md
├── packaging/winget/               # WinGet manifest templates rendered during GitHub Releases
├── site/                           # Static website & feature comparison (index.html, styles.css, app.js)
├── build.ps1                       # Reproducible local release build script (`.\build.ps1 -Test`)
├── CHANGELOG.md                    # CalVer release history & Windows Defender evolution log
├── VERSION.json                    # Machine-readable CalVer metadata & tested Defender platform matrix
├── go.mod
└── LICENSE
```

---

## Architecture Overview

1. **Direct Policy + DCOM WMI Governance (Zero Fake-AV or Service-Killer Hacks):**
   - Rather than registering a dummy third-party antivirus in Windows Security Center (which forces `MsMpEng.exe` into passive mode and requires an MVI ELAM kernel certificate) or gutting the `WinDefend` service via `TrustedInstaller` tricks, ShieldSheriff writes native Group Policy keys under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` and `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center` while synchronizing live preferences into `MsMpEng.exe` via DCOM WMI (`ROOT\Microsoft\Windows\Defender:MSFT_MpPreference`).
   - Because it uses DCOM directly rather than PowerShell's `Set-MpPreference` CIM cmdlets, ShieldSheriff works even when the `WinRM` / `WSMan` service is disabled.

2. **Execution Modes & Privilege Boundaries:**
   - **No-Arg Default (`shiesh.exe`):** Runs a read-only live status inspection and exits `0` immediately. This prevents unexpected UAC prompts from terminal invocations and satisfies automated package validation (such as WinGet's headless post-install check).
   - **Read-Only UI (`shiesh.exe ui`):** Starts a window-bound localhost server (`127.0.0.1:38419`) and native WebView2 window without creating a system tray icon or starting the background enforcement loop, exiting cleanly when the window closes. Clicking **Admin** inside the UI relaunches with `ui --replace --elevate`.
   - **Elevated UI / System Tray (`shiesh.exe ui --elevate` / `tray --elevate`):** Acquires the single-instance mutex (`Local\ShieldSheriffCommandCenterInstance`), starts the persistent Win32 `Shell_NotifyIconW` system tray icon, and runs the drift/process-watch governor loop.
   - **Windows Service (`shiesh.exe service install` / `service run`):** Registers and runs under the Windows Service Control Manager (SCM) as `LocalSystem` (`SYSTEM`) for headless 24/7 enforcement across reboots.

3. **Host State & Persistence Locations:**
   - **Configuration:** `%ProgramData%\ShieldSheriff\config.json` (when elevated) or `%LOCALAPPDATA%\ShieldSheriff\config.json` (unprivileged fallback).
   - **Logon Startup:** Scheduled Task named `ShieldSheriff Tray` (`HighestAvailable` run level, executing `"<exePath>" tray --no-elevate`).
   - **Windows Service:** SCM service named `ShieldSheriff` (executing `"<exePath>" service run`).

---

## Building & Testing Locally

### Prerequisites
- **OS:** Windows 11 (24H2 / 25H2 baseline)
- **Go:** Go `1.25+` (pinned in `go.mod`, compiled with `CGO_ENABLED=0`)
- **PowerShell:** PowerShell 7 (`pwsh`) or Windows PowerShell

### Build Script (`build.ps1`)
Use `build.ps1` to run static analysis, execute all unit tests, compile `bin\shiesh.exe` with version metadata injected from `VERSION.json`, and generate `bin\ShieldSheriff.lnk` (a convenience shortcut configured to launch `shiesh.exe ui --elevate`):

```powershell
# Build and run go vet + unit tests:
.\build.ps1 -Test

# Stop any running shiesh.exe instance before building:
.\build.ps1 -Test -StopRunning
```

### Manual Go Commands
```powershell
# Static analysis and full test suite:
go vet -mod=readonly ./...
go test -mod=readonly -count=1 -v ./...

# Direct binary build:
$env:CGO_ENABLED = "0"
go build -mod=readonly -trimpath -ldflags="-s -w" -o bin\shiesh.exe ./cmd/shieldsheriff
```

### Windows Resource Generation (`.syso`)
If you modify `cmd/shieldsheriff/winres/winres.json` or application icons, regenerate the embedded `.syso` resource files with:

```powershell
go generate ./cmd/shieldsheriff
```

---

## Versioning (`CalVer`) & Releases

ShieldSheriff uses **Calendar Versioning (`YYYY.0M.MICRO`)** because Microsoft Defender (`MsMpEng.exe` / `WdFilter.sys`) and Windows Security Center (`SecurityHealthService.exe`) evolve on Microsoft's monthly Patch Tuesday and Windows 11 cumulative update schedule.

`TestVersionSync` in [`internal/version/version_test.go`](internal/version/version_test.go) enforces that the release version and date stay synchronized across:
1. [`VERSION.json`](VERSION.json)
2. [`internal/version/version.go`](internal/version/version.go)
3. [`CHANGELOG.md`](CHANGELOG.md)

Pushing a version tag (`vYYYY.0M.MICRO`) triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which runs the test suite, builds portable `amd64` and `arm64` `.zip` archives, computes `SHA256SUMS.txt`, renders the WinGet manifests from [`packaging/winget/`](packaging/winget/README.md), and publishes the GitHub Release.
