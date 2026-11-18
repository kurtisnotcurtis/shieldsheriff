# ShieldSheriff CLI & Automation Reference

ShieldSheriff includes a full command-line interface (`shiesh.exe` / `shiesh`) for scripting, unattended setup, and inspecting live Windows Defender state.

> **Requirements:** Windows 11 (`x64` or `arm64`). Reading status (`shiesh` / `shiesh status`) works without elevation. Applying presets, changing settings, running the persistent System Tray, or installing the background service requires Administrator privileges (or `--elevate` for a UAC prompt).

---

## Launching the UI & System Tray

```powershell
# Launch Dashboard UI + persistent System Tray (prompts for Administrator UAC):
shiesh ui --elevate

# Open Dashboard UI in Read-Only mode (no tray; click "Admin" inside the app to elevate):
shiesh ui

# Launch minimized directly to the persistent System Tray (requires Admin / --elevate):
shiesh tray --elevate
```

---

## Inspecting Live Defender Status

Running `shiesh` with no arguments (or `shiesh status`) prints live Defender protection states, Tamper Protection status, and configuration drift, then exits `0` without modifying your system:

```powershell
shiesh
shiesh status

# Machine-readable JSON output for scripts:
shiesh status --json
shiesh version --json
```

---

## Applying Presets & Individual Settings

```powershell
# Apply the default "Local Protection" preset (prompts for Admin UAC with --elevate):
shiesh apply --elevate

# Apply a specific preset (local-protection, workstation, on-demand, cloud-local):
shiesh apply --preset workstation --elevate

# Customize individual engine & notification settings (run from an elevated terminal):
shiesh set realtime=on behavior=off script=off cloud=off samples=never nags=off

# Auto-pause Real-Time Protection whenever specified processes are running:
shiesh set watch=cargo.exe,msbuild.exe,link.exe,rustc.exe
```

### Preset IDs

| ID | Name | Summary |
| :--- | :--- | :--- |
| `local-protection` | Local Protection *(Default)* | Real-Time & Behavior ON, Cloud OFF, Sample Submission OFF, all nags silenced |
| `workstation` | Workstation | Real-Time & IOAV ON, Behavior & Script hooks OFF, auto-pauses on `cargo.exe`, `msbuild.exe`, `link.exe`, `rustc.exe` |
| `on-demand` | On-Demand Only | Real-Time Protection OFF permanently (no 24h reset); manual scans & definition updates active |
| `cloud-local` | Cloud + Local | All local engines + Cloud Protection (MAPS) ON, Sample Submission OFF, all nags silenced |

### Granular `shiesh set` Keys

| Key | Values | Description |
| :--- | :--- | :--- |
| `realtime` (`rtp`) | `on` \| `off` | Real-Time Protection |
| `behavior` (`bm`) | `on` \| `off` | Behavior Monitoring |
| `ioav` (`downloads`) | `on` \| `off` | Downloaded Files & Attachments scanning |
| `script` (`amsi`) | `on` \| `off` | Script Scanning (AMSI) |
| `network` (`net`) | `off` \| `block` \| `audit` | Network Protection (Exploit Guard) |
| `cloud` (`maps`) | `off` \| `basic` \| `advanced` | Cloud Protection (MAPS) |
| `samples` (`submit`) | `never` \| `prompt` \| `safe` \| `all` | Automatic Sample Submission |
| `nags` (`notifications`) | `off` \| `on` | Suppress Windows Security toast nags (`off` = silenced) |
| `systray` | `mute` \| `show` | Hide default Windows Security tray icon |
| `watch` | `proc1.exe,proc2.exe` \| `none` | Processes that trigger Auto-Pause of Real-Time Protection |

---

## Pausing, Scanning & Background Service

```powershell
# Temporarily pause Real-Time Protection for 30 minutes, or resume immediately:
shiesh pause 30
shiesh resume

# Run an on-demand Defender Quick Scan or definition update (works even in On-Demand Only mode):
shiesh scan
shiesh update

# Install or remove the 24/7 background Windows Service (runs as SYSTEM across reboots):
shiesh service install
shiesh service uninstall
```
