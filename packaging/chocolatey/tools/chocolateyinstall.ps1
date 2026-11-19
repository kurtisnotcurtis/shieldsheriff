$ErrorActionPreference = 'Stop'

$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

$urlAmd64      = 'https://github.com/kurtisnotcurtis/shieldsheriff/releases/download/__TAG__/shieldsheriff-__VERSION__-windows-amd64.zip'
$checksumAmd64 = '__SHA256_AMD64__'

$urlArm64      = 'https://github.com/kurtisnotcurtis/shieldsheriff/releases/download/__TAG__/shieldsheriff-__VERSION__-windows-arm64.zip'
$checksumArm64 = '__SHA256_ARM64__'

if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    $url      = $urlArm64
    $checksum = $checksumArm64
} else {
    $url      = $urlAmd64
    $checksum = $checksumAmd64
}

$packageArgs = @{
    packageName   = $env:ChocolateyPackageName
    unzipLocation = $toolsDir
    url           = $url
    checksum      = $checksum
    checksumType  = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

$programsDir = [Environment]::GetFolderPath('CommonPrograms')
if (-not $programsDir -or -not (Test-Path $programsDir)) {
    $programsDir = [Environment]::GetFolderPath('Programs')
}

if ($programsDir) {
    $shortcutFilePath = Join-Path $programsDir 'ShieldSheriff.lnk'
    Install-ChocolateyShortcut `
        -ShortcutFilePath $shortcutFilePath `
        -TargetPath (Join-Path $toolsDir 'shiesh.exe') `
        -Arguments 'ui --elevate' `
        -WorkingDirectory $toolsDir `
        -Description 'Launch ShieldSheriff Command Center UI & System Tray'
}
