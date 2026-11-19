$ErrorActionPreference = 'Stop'

foreach ($folder in @('CommonPrograms', 'Programs')) {
    $programsDir = [Environment]::GetFolderPath($folder)
    if ($programsDir) {
        $shortcutPath = Join-Path $programsDir 'ShieldSheriff.lnk'
        if (Test-Path $shortcutPath) {
            Remove-Item $shortcutPath -Force
        }
    }
}
