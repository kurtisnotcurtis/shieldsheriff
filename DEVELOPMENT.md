# ShieldSheriff Development & Architecture Guide

This document covers the repository layout, internal Windows 11 / Defender architecture, local build and test workflows, and release packaging for **ShieldSheriff**.

For end-user installation and usage instructions, see [README.md](README.md).

---

## Project Structure

```text
shieldsheriff/
├── cmd/shieldsheriff/
│   ├── main.go                     # CLI, System Tray & Dashboard UI entry point
│   ├── main_test.go                # CLI argument, validation & flag tests
│   ├── instance.go                 # Single-instance named mutex, focus handoff & tray IPC client
│   ├── console_windows.go          # Console window suppression for GUI/Tray launches
│   └── winres/                     # Windows application manifest & icon resource definitions
├── internal/
│   ├── defender/
│   │   ├── state.go                # Mode, Policy, Preferences, PauseState, Status, and Presets
│   │   ├── backend.go              # Testable OS Backend interface (Registry, exec, elevation)
│   │   ├── backend_windows.go      # Production Windows Registry/exec implementation via x/sys/windows
│   │   ├── settings.go             # Single source of truth for managed registry keys & pre-change snapshot
│   │   ├── inspect.go              # Pure live Registry & filesystem inspector + compliance evaluator
│   │   ├── enforce.go              # Policy locks, live Defender keys, DCOM Set-MpPreference & full revert
│   │   └── elevation.go            # Token elevation check & UAC self-elevation ("runas")
│   ├── sheriff/
│   │   ├── config.go               # Atomic config.json v2 storage (with automatic v1 migration)
│   │   ├── governor.go             # Pure Snapshot(), Mode-gated enforcement, drift healer & backoff
│   │   ├── process_windows.go      # Win32 Toolhelp32 + full-path suffix process watcher
│   │   ├── runtime_windows.go      # Admin-only control.json & focus.json loopback IPC discovery
│   │   ├── startup.go              # Elevated logon Task Scheduler registration (`ShieldSheriff Tray`)
│   │   └── update.go               # GitHub Releases update checker
│   ├── tray/
│   │   ├── icon.go                 # Procedural 32-bit ARGB preset, pause, passive & brand HICON renderer
│   │   └── systray.go              # Thread-safe Win32 Shell_NotifyIconW tray (with TaskbarCreated recovery)
│   ├── ui/
│   │   ├── server.go               # Authenticated 127.0.0.1 API server & WebView2 native window host
│   │   ├── theme.go                # Windows 11 Dark/Light mode, DWM accent & system UI font reader
│   │   ├── window.go               # Windows 11 Mica/caption chrome & tracked-HWND focus/close
│   │   └── dashboard.html          # Windows 11 Settings-style dual-pane UI with staged Apply Now
│   └── version/
│       ├── version.go              # CalVer (YYYY.0M.MICRO) release & Defender platform compatibility metadata
│       └── version_test.go         # Enforces version sync across VERSION.json, version.go, and CHANGELOG.md
├── packaging/
│   ├── chocolatey/                 # Chocolatey .nuspec & install/uninstall templates
│   ├── scoop/                      # Scoop manifest template with checkver & autoupdate
│   └── winget/                     # WinGet manifest templates rendered during GitHub Releases
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
   - Rather than registering a dummy third-party antivirus in Windows Security Center (which forces `MsMpEng.exe` into passive mode and requires an MVI ELAM kernel certificate) or gutting the `WinDefend` service via `TrustedInstaller` tricks, ShieldSheriff writes native Group Policy keys under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` and `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center`, updates the corresponding live Defender keys, and invokes PowerShell's `Set-MpPreference` over an explicit DCOM `CimSession` (bounded by a 15-second timeout) so `MsMpEng.exe` reloads immediately even when `WinRM` / `WSMan` is disabled.
   - On first apply, ShieldSheriff captures a pre-change snapshot of every managed registry value under `HKLM\SOFTWARE\ShieldSheriff\Backup\SnapshotJSON` so entering **Passive Mode** restores every modified key cleanly.

2. **Single Governor & Authenticated Local Control:**
   - **No-Arg Default (`shiesh.exe`):** Runs a pure read-only live status inspection and exits `0` immediately.
   - **Read-Only UI (`shiesh.exe ui`):** Starts a window-bound localhost server (`127.0.0.1:38419`, or ephemeral fallback) with a per-launch random API token and native WebView2 window without creating a system tray icon or starting the background enforcement loop, exiting cleanly when the window closes.
   - **Elevated UI / System Tray (`shiesh.exe ui --elevate` / `tray --elevate`):** Acquires the single-instance mutex (`Local\ShieldSheriffInstance`), runs the single authoritative Governor loop, and publishes its authenticated loopback endpoint to `%ProgramData%\ShieldSheriff\control.json` (protected with an Administrators + SYSTEM-only Windows DACL).
   - **Elevated CLI Coordination:** Elevated CLI commands (`apply`, `set`, `pause`, `resume`, `passive`) forward mutations directly to any running elevated tray Governor over the authenticated loopback API so CLI and tray never fight over state.

3. **Host State & Persistence Locations:**
   - **Configuration:** `%ProgramData%\ShieldSheriff\config.json` (atomic writes; schema v2 with automatic v1 migration) or `%LOCALAPPDATA%\ShieldSheriff\config.json` (unprivileged fallback).
   - **Logon Startup:** Scheduled Task named `ShieldSheriff Tray` (`HIGHEST` run level, executing `"<exePath>" tray`).

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

### Website Preview Screenshot (`scripts/capture-preview.ps1`)
To refresh [`site/preview.png`](site/preview.png) from a live `shiesh.exe ui` window:

```powershell
.\scripts\capture-preview.ps1 -Build -StopRunning
```

---

## Versioning (`CalVer`) & Releases

ShieldSheriff uses **Calendar Versioning (`YYYY.0M.MICRO`)** because Microsoft Defender (`MsMpEng.exe` / `WdFilter.sys`) and Windows Security Center (`SecurityHealthService.exe`) evolve on Microsoft's monthly Patch Tuesday and Windows 11 cumulative update schedule.

`TestVersionSync` in [`internal/version/version_test.go`](internal/version/version_test.go) enforces that the release version and date stay synchronized across:
1. [`VERSION.json`](VERSION.json)
2. [`internal/version/version.go`](internal/version/version.go)
3. [`CHANGELOG.md`](CHANGELOG.md)

Pushing a version tag (`vYYYY.0M.MICRO`) triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which runs the test suite, builds portable `amd64` and `arm64` `.zip` archives, computes `SHA256SUMS.txt`, renders manifests/packages for [WinGet](packaging/winget/README.md), [Scoop](packaging/scoop/README.md), and [Chocolatey](packaging/chocolatey/README.md), publishes the GitHub Release, and optionally runs automated publish jobs when `WINGET_ACC_TOKEN`, `SCOOP_BUCKET_TOKEN`, or `CHOCO_API_KEY` secrets are configured.
