param(
    [switch]$Build,
    [switch]$StopRunning,
    [string]$OutPath = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutPath) {
    $OutPath = Join-Path $repoRoot "site\preview.png"
}

$exePath = Join-Path $repoRoot "bin\shiesh.exe"

$running = Get-Process -Name "shiesh" -ErrorAction SilentlyContinue
if ($running -and $StopRunning) {
    $running | Stop-Process -Force
    Start-Sleep -Milliseconds 300
    $running = Get-Process -Name "shiesh" -ErrorAction SilentlyContinue
}
if ($running) {
    throw "Cannot capture preview: 'shiesh.exe' is already running (holding port 38419 / single-instance lock). Exit it or re-run with -StopRunning."
}

if ($Build) {
    & (Join-Path $repoRoot "build.ps1")
    if ($LASTEXITCODE -ne 0) { throw "build.ps1 failed" }
}

if (-not (Test-Path $exePath)) {
    throw "Missing '$exePath'. Run .\build.ps1 first or pass -Build."
}

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public class ShieldSheriffPreviewCap {
    public delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hwnd, StringBuilder sb, int max);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
"@

[ShieldSheriffPreviewCap]::SetProcessDPIAware() | Out-Null

$proc = Start-Process -FilePath $exePath -ArgumentList "ui" -PassThru
try {
    $targetPid = [uint32]$proc.Id
    $script:foundHwnd = [IntPtr]::Zero

    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 300
        [ShieldSheriffPreviewCap]::EnumWindows({
            param($hwnd, $lp)
            [uint32]$wpid = 0
            [ShieldSheriffPreviewCap]::GetWindowThreadProcessId($hwnd, [ref]$wpid) | Out-Null
            if ($wpid -eq $targetPid -and [ShieldSheriffPreviewCap]::IsWindowVisible($hwnd)) {
                $sb = New-Object System.Text.StringBuilder 256
                [ShieldSheriffPreviewCap]::GetWindowTextW($hwnd, $sb, 256) | Out-Null
                if ($sb.ToString() -eq "ShieldSheriff") {
                    $script:foundHwnd = $hwnd
                    return $false
                }
            }
            return $true
        }, [IntPtr]::Zero) | Out-Null
        if ($script:foundHwnd -ne [IntPtr]::Zero) { break }
    }

    if ($script:foundHwnd -eq [IntPtr]::Zero) {
        throw "Timed out waiting for the ShieldSheriff UI window."
    }

    # Allow WebView2 content to finish rendering.
    Start-Sleep -Seconds 3

    $rect = New-Object ShieldSheriffPreviewCap+RECT
    [ShieldSheriffPreviewCap]::GetWindowRect($script:foundHwnd, [ref]$rect) | Out-Null
    $w = $rect.Right - $rect.Left
    $h = $rect.Bottom - $rect.Top
    if ($w -le 0 -or $h -le 0) {
        throw "Invalid window bounds (${w}x${h})."
    }

    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    try {
        $gfx = [System.Drawing.Graphics]::FromImage($bmp)
        try {
            $hdc = $gfx.GetHdc()
            try {
                $ok = [ShieldSheriffPreviewCap]::PrintWindow($script:foundHwnd, $hdc, 2)
                if (-not $ok) {
                    throw "PrintWindow failed for HWND $($script:foundHwnd)."
                }
            } finally {
                $gfx.ReleaseHdc($hdc)
            }
        } finally {
            $gfx.Dispose()
        }
        $bmp.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $bmp.Dispose()
    }

    Write-Host "Captured ${w}x${h} preview to $OutPath"
} finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}
