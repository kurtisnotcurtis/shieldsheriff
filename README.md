<p align="center">
  <img src="site/logo.svg" alt="ShieldSheriff Logo" width="84" height="84" />
</p>

<h1 align="center">ShieldSheriff</h1>

<p align="center">
  <strong>Granular, Nag-Free Control for Windows 11 Defender.</strong><br />
  <a href="https://kurtisnotcurtis.github.io/shieldsheriff/">Website &amp; Comparison</a> ·
  <a href="https://github.com/kurtisnotcurtis/shieldsheriff/releases">Download Releases</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="DEVELOPMENT.md">Developer Guide</a>
</p>

<p align="center">
  <img src="site/preview.png" alt="ShieldSheriff Command Center UI on Windows 11" />
</p>

---

## Why ShieldSheriff?

Windows 11's built-in Microsoft Defender (`MsMpEng.exe`) is a capable local antivirus engine, but its notification layer (`SecurityHealthService.exe` / `SecurityHealthSystray.exe`) relentlessly nags whenever you intentionally turn off **Cloud-delivered protection**, **Automatic sample submission**, **Tamper protection**, or **Real-time protection**—and Windows Updates regularly flip your settings back on.

**ShieldSheriff** is a lightweight (~5 MB), single-binary Windows 11 Defender governor that keeps Defender under your rules using native Windows policies rather than service-killing hacks or fake third-party antivirus registration:

- **Granular Engine Control:** Keep `WinDefend` alive while independently controlling **Real-Time Protection**, **Behavior Monitoring**, **Downloads & Attachments (IOAV)**, **Script Scanning (AMSI)**, **Network Protection**, **Cloud Protection (MAPS)**, and **Sample Submission**.
- **Silence Security Center Nags:** Suppresses Windows Security toast notifications and optionally hides the Windows Security system tray icon (with automatic registry backup and restore).
- **Auto-Heal Update Resets:** Periodically checks your live Defender state (default every 15s, configurable) and restores your chosen settings if a Windows Update or background task resets them.
- **Timed Pause & Auto-Pause on Builds:** Temporarily pause Real-Time Protection for `15m`, `30m`, `1h`, or `4h`, or pause automatically whenever specified compilers, linkers, or games (`cargo.exe`, `msbuild.exe`, `link.exe`, `rustc.exe`, etc.) are running.

---

## Built-In Presets

Choose a one-click preset from the **Command Center UI**, **System Tray menu**, or **CLI** (`shiesh elect --preset <id> --elevate`), or customize every toggle individually:

| Preset | ID | What It Does |
| :--- | :--- | :--- |
| **Quiet Guardian** *(Default)* | `quiet-guardian` | **Local Real-Time ON**, Cloud Protection **OFF**, Sample Submission **OFF**, all Windows Security nags **Silenced**. |
| **Developer Workstation** | `dev-workstation` | Keeps core Real-Time scanning ON, turns heavy **Behavior Monitoring** & **Script Scanning** hooks **OFF**, and auto-pauses scanning while `cargo.exe`, `rustc.exe`, `msbuild.exe`, or `link.exe` run. |
| **On-Demand Only** | `on-demand-only` | Turns **Real-Time Protection OFF permanently** (no 24-hour reset) while keeping manual **Quick Scans** and **Signature Updates** working. |
| **Full Shield (No Nags)** | `full-shield-no-nag` | Keeps **Local + Cloud Protection ON**, turns automatic file **Sample Uploads OFF**, and silences all Security Center nags. |

---

## Installation

> **Requirements:** Windows 11 (`x64` or `arm64`). Administrator privileges (UAC) are required to apply Defender policies, run the persistent System Tray, or install the background service.

### Option 1: Install via WinGet
```powershell
winget install kurtisnotcurtis.ShieldSheriff
```
WinGet installs `shiesh.exe` and adds the `shiesh` command alias to your `PATH`.

### Option 2: Portable `.zip` Archive
1. Download `shieldsheriff-<version>-windows-amd64.zip` (or `arm64.zip`) from [GitHub Releases](https://github.com/kurtisnotcurtis/shieldsheriff/releases).
2. Extract `shiesh.exe` into a permanent folder (for example, `C:\Tools\ShieldSheriff\`).
   > **Note for Portable Users:** If you enable **Start in System Tray at Windows Logon** or install the **Background Service**, Windows registers the current path of `shiesh.exe`. Place `shiesh.exe` in its permanent folder before enabling startup/service options.

### One-Time Prerequisite: Turn Off Tamper Protection
Windows Defender's **Tamper Protection** blocks local apps and Group Policy keys from changing Defender settings. Before applying policies for the first time:
1. Open **Windows Security → Virus & threat protection → Manage settings** (or run `start windowsdefender://threatsettings`).
2. Toggle **Tamper Protection** to **Off** once.
3. ShieldSheriff will silence the resulting Tamper Protection warning notification automatically once your Standing Orders are applied.

---

## Getting Started

*(If you extracted the portable `.zip` without adding it to your `PATH`, replace `shiesh` below with `.\shiesh.exe`.)*

### 1. Launch the Command Center UI & System Tray
```powershell
# Launch full Command Center UI + persistent System Tray (prompts for Administrator UAC):
shiesh ui --elevate

# Or open the Command Center UI in Read-Only mode first (no tray; click "Admin" inside the app to elevate):
shiesh ui

# Launch minimized directly to the persistent System Tray:
shiesh tray --elevate
```
- **Safe First Run:** On first launch, ShieldSheriff opens in **Passive / Read-Only** state and reflects your PC's current Defender configuration without changing anything until you click **Apply Now**.
- **Windows 11 Native Look:** Uses WebView2 with Windows 11 Mica backdrop and automatically follows your system Dark/Light theme and accent color.
- **Three-State System Tray Icon:**
  - **Preset Mode:** Displays the active preset shield (**Quiet Guardian** blue shield, **Developer Workstation** sky-blue `<>`, **On-Demand Only** red `-`, **Full Shield** green checkmark, or **Custom**).
  - **Pause Mode:** Amber shield with `||` pause bars while Real-Time Protection is paused by timer or a watched process.
  - **Passive Mode:** Hollow slate shield outline when ShieldSheriff is not actively enforcing policies.

### 2. Inspect Live Defender Status (Read-Only Default)
Running `shiesh` with no arguments (or `shiesh status`) inspects live Defender engines, Tamper Protection, and policy drift without modifying your system or prompting for UAC:
```powershell
shiesh
# Machine-readable JSON output:
shiesh status --json
```

### 3. Control Defender from the CLI
```powershell
# Apply the default "Quiet Guardian" preset (prompts for Admin UAC with --elevate):
shiesh elect --elevate

# Apply a specific preset (quiet-guardian, dev-workstation, on-demand-only, full-shield-no-nag):
shiesh elect --preset dev-workstation --elevate

# Customize individual engine & notification settings (run from an elevated terminal):
shiesh order realtime=on behavior=off script=off cloud=off samples=never nags=off

# Auto-pause Real-Time Protection whenever specified processes are running:
shiesh order watch=cargo.exe,msbuild.exe,link.exe,rustc.exe

# Temporarily pause Real-Time Protection for 30 minutes, or resume immediately:
shiesh pause 30
shiesh resume

# Run an on-demand Defender Quick Scan or signature update (works even in On-Demand Only mode):
shiesh scan
shiesh update

# Install or remove the 24/7 background Windows Service (runs as SYSTEM across reboots):
shiesh service install
shiesh service uninstall
```

---

## Reverting to Windows Defaults & Uninstalling

1. **Revert Defender Policies:** Open the Command Center UI (`shiesh ui --elevate`) or right-click the System Tray icon and select **Passive Mode (Stop Enforcing)** to remove ShieldSheriff's policy locks and restore standard Windows Security notifications.
2. **Remove Background Service / Startup (if enabled):**
   - Turn off **Start in Tray at Logon** and **Windows Service** in the **Settings** tab of the UI (or run `shiesh service uninstall` as Administrator).
3. **Uninstall the Binary:**
   - **WinGet:** `winget uninstall kurtisnotcurtis.ShieldSheriff`
   - **Portable `.zip`:** Delete `shiesh.exe` and optional config folder `C:\ProgramData\ShieldSheriff`.

---

## Versioning, Development & License

- **Calendar Versioning (`CalVer`):** ShieldSheriff uses `YYYY.0M.MICRO` versioning to track Windows 11 cumulative updates and monthly Microsoft Defender platform releases. See [CHANGELOG.md](CHANGELOG.md) and [VERSION.json](VERSION.json).
- **Building from Source & Repo Structure:** See [DEVELOPMENT.md](DEVELOPMENT.md) for the repository layout, architecture internals, and `.\build.ps1` build/test instructions.
- **License:** Released under the [MIT License](LICENSE).
