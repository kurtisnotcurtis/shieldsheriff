param(
    [switch]$Test
)

$ErrorActionPreference = "Stop"

if ($Test) {
    go vet ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    go test -count=1 ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

New-Item -ItemType Directory -Force -Path bin | Out-Null
go build -trimpath -ldflags="-s -w" -o bin\shieldsheriff.exe ./cmd/shieldsheriff
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Built bin\shieldsheriff.exe"
