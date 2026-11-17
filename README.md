<p align="center">
  <img src="site/logo.svg" alt="ShieldSheriff Logo" width="84" height="84" />
</p>

# ShieldSheriff

**Granular, Nag-Free Control for Windows 11 Defender.**

> **Platform & Privileges:** Windows 11 only. ShieldSheriff prompts for Administrator (UAC) on launch to apply Defender policies (falling back to Read-Only mode if declined). Ensure **Tamper Protection** is toggled `OFF` once in `windowsdefender://threatsettings` so Defender honors local policy locks.

Windows 11's built-in Microsoft Defender (`MsMpEng.exe`) is a solid antivirus engine, but its notification layer (`SecurityHealthService.exe` / `SecurityHealthSystray.exe`) relentlessly nags when you intentionally turn off **Cloud-delivered protection**, **Automatic sample submission**, **Tamper protection**, or **Real-time protection**—and Windows Updates or Defender background tasks frequently flip your settings back on.

Rather than registering as a fake third-party antivirus in Windows Security Center (which causes `MsMpEng.exe` to automatically disable its own real-time protection and requires an MVI ELAM kernel certificate), **ShieldSheriff** manages Defender directly using native Windows policies:
- **Granular Protection Engines:** Keeps `WinDefend` alive while giving you direct control over `Real-Time Protection`, `Behavior Monitoring`, `Downloads & Attachments (IOAV)`, `Script Scanning (AMSI)`, `Network Protection`, `Cloud Protection (MAPS)`, and `Sample Submission`.
- **Silence Security Nags:** Applies Windows Security Center notification & UX policies (`DisableNotifications`, `DisableEnhancedNotifications`, `Notification_Suppress`) and optionally hides the default `SecurityHealthSystray.exe` icon (with automatic registry backup & restore).
- **Auto-Heal Settings Drift:** Periodically inspects live Registry & WMI (`MSFT_MpPreference`) state at your configured interval (default 15s) and restores your chosen settings if Defender or Windows Update resets them.
- **Pause Protection & Auto-Pause Watchlist:** Temporarily pause Real-Time Protection for 15m / 30m / 1h / 4h, or automatically whenever specified build tools or games (`cargo.exe`, `msbuild.exe`, `link.exe`, `rustc.exe`, etc.) are running.

---

## Project Structure

```
shieldsheriff/
├── cmd/shieldsheriff/
│   ├── main.go                     # CLI, System Tray, Command Center UI & Windows Service entry point
│   └── instance.go                 # Single-instance named mutex & Command Center focus handoff
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
│   │   └── dashboard.html          # Windows 11 Settings-style dual-pane UI with staged Apply Now
│   └── version/
│       └── version.go              # CalVer (YYYY.0M.MICRO) release & Defender platform compatibility metadata
├── build.ps1                       # Reproducible local release build script (`.\build.ps1 -Test`)
├── site/                           # Static marketing & comparison website (index.html, styles.css, app.js)
├── CHANGELOG.md                    # CalVer release history & Windows Defender evolution log
├── VERSION.json                    # Machine-readable CalVer metadata & tested Defender platform matrix
├── go.mod
└── LICENSE
```

---

## Quick Start

### 1. Build
```powershell
.\build.ps1 -Test
# (or: go build -trimpath -ldflags="-s -w" -o bin\shiesh.exe ./cmd/shieldsheriff)
```

### 2. Launch ShieldSheriff (UI & System Tray)
```powershell
.\bin\shiesh.exe
```
- **Windows 11 Settings-Style UI (WebView2 + Mica):** Adapts automatically to your Windows 11 Dark/Light mode, accent color, and system font. On first run (no `config.json`), ShieldSheriff shows your current PC settings without modifying anything until you stage changes and click **Apply Now** (with one-time consent for logon startup, configurable Auto-Heal interval, and startup update checks).
- **Three-State System Tray:**
  - **Preset Mode:** Displays the active preset's shield icon (**On-Demand Only** red `-`, **Developer Workstation** sky-blue `<>`, **Quiet Guardian** blue shield, **Full Shield** green checkmark, or **Custom**).
  - **Pause Mode:** Amber shield with `||` pause bars when temporarily paused by timer or watched build process.
  - **Passive Mode:** Hollow slate shield outline when not enforcing (first run or after reverting ShieldSheriff policies).
- **Single-Instance Locking:** Relaunching focuses the existing window instead of opening duplicates.

### 3. Inspect Live Defender Status (CLI)
```powershell
.\bin\shiesh.exe status
```

### 4. Apply a Preset or Granular Settings (CLI)
```powershell
# Apply the default "Quiet Guardian" preset (Real-Time ON, Cloud OFF, Sample Submission OFF, Nags Silenced):
.\bin\shiesh.exe elect --elevate

# Keep Real-Time ON, turn Behavior/Script scanning OFF, Cloud & Sample uploads OFF, and silence all nags:
.\bin\shiesh.exe order realtime=on behavior=off script=off cloud=off samples=never nags=off

# Automatically pause Real-Time Protection whenever cargo.exe or msbuild.exe is running:
.\bin\shiesh.exe order watch=cargo.exe,msbuild.exe

# Manually pause Real-Time Protection for 30 minutes, then auto-resume:
.\bin\shiesh.exe pause 30

# Install as a 24/7 background SYSTEM Windows Service across reboots:
.\bin\shiesh.exe service install

# Inspect CalVer release & tested Windows Defender platform compatibility:
.\bin\shiesh.exe version
```

---

## Versioning (`CalVer`) & Changelog

ShieldSheriff uses **Calendar Versioning (`YYYY.0M.MICRO`)** because Windows Defender (`MsMpEng.exe` / `WdFilter.sys`) and Windows Security Center (`SecurityHealthService.exe`) evolve on Microsoft's monthly Patch Tuesday and Windows 11 cumulative update schedule rather than static library SemVer contracts.

- See [`CHANGELOG.md`](CHANGELOG.md) for the full release history and Windows Defender platform changes.
- See [`VERSION.json`](VERSION.json) for machine-readable release and compatibility metadata.

---

## License

Released under the [MIT License](LICENSE).
