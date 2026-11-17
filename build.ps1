param(
    [switch]$Test,
    [switch]$StopRunning
)

$ErrorActionPreference = "Stop"

$vj = Get-Content VERSION.json -Raw | ConvertFrom-Json
$ver = $vj.version
$relDate = $vj.releasedOn

$binDir = Join-Path $PSScriptRoot "bin"
$exePath = Join-Path $binDir "shiesh.exe"
$lnkPath = Join-Path $binDir "ShieldSheriff.lnk"

function Test-FileLocked([string]$Path) {
    if (-not (Test-Path $Path)) { return $false }
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $fs.Close()
        return $false
    } catch {
        return $true
    }
}

$running = Get-Process -Name "shiesh" -ErrorAction SilentlyContinue
if ($running -and $StopRunning) {
    $running | Stop-Process -Force
    Start-Sleep -Milliseconds 300
    $running = Get-Process -Name "shiesh" -ErrorAction SilentlyContinue
}

if ($running -or (Test-FileLocked $exePath)) {
    throw "Build failed: '$exePath' is currently in use (ShieldSheriff is still running). Exit the running tray/UI process or re-run with -StopRunning."
}

if ($Test) {
    go vet -mod=readonly ./...
    if ($LASTEXITCODE -ne 0) { throw "go vet failed with exit code $LASTEXITCODE" }
    go test -mod=readonly -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw "go test failed with exit code $LASTEXITCODE" }
}

$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$ldflags = "-s -w -X shieldsheriff/internal/version.Version=$ver -X shieldsheriff/internal/version.ReleasedOn=$relDate"

New-Item -ItemType Directory -Force -Path $binDir | Out-Null
go build -mod=readonly -trimpath -ldflags="$ldflags" -o $exePath ./cmd/shieldsheriff
if ($LASTEXITCODE -ne 0) { throw "go build failed with exit code $LASTEXITCODE" }

$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut($lnkPath)
$sc.TargetPath = $exePath
$sc.Arguments = "ui --elevate"
$sc.WorkingDirectory = $binDir
$sc.Description = "Launch ShieldSheriff Command Center UI & System Tray"
$sc.WindowStyle = 7
$sc.Save()

Write-Host "Built bin\shiesh.exe, bin\ShieldSheriff.lnk (v$ver)"
