param(
    [switch]$Test
)

$ErrorActionPreference = "Stop"

$vj = Get-Content VERSION.json -Raw | ConvertFrom-Json
$ver = $vj.version
$relDate = $vj.releasedOn

if ($Test) {
    go vet -mod=readonly ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    go test -mod=readonly -count=1 ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$ldflags = "-s -w -X shieldsheriff/internal/version.Version=$ver -X shieldsheriff/internal/version.ReleasedOn=$relDate"

New-Item -ItemType Directory -Force -Path bin | Out-Null
go build -mod=readonly -trimpath -ldflags="$ldflags" -o bin\shiesh.exe ./cmd/shieldsheriff
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Built bin\shiesh.exe (v$ver)"
