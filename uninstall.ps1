# Remove the Claude access guard (ipguard) on Windows: the Task Scheduler task is stopped and
# deleted. Settings, journal and binary stay — the settings hold the secret, the journal holds
# the history of refusals. The proxy is dropped from the claude settings separately:
# `ipguard disable`.
#
# The command takes no arguments, but PowerShell sometimes passes the `--` separator to the
# script as a string: it is stripped below, otherwise cobra would refuse (`Args: cobra.NoArgs`).
$ErrorActionPreference = 'Stop'

Set-Location -Path $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error 'ipguard: Go is required — https://go.dev/dl/'
}

$build = Join-Path $env:TEMP ('ipguard-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $build | Out-Null

try {
    $env:GOWORK = 'off'
    $binary = Join-Path $build 'ipguard.exe'

    & go build -trimpath -o $binary ./cmd/ipguard
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'ipguard: build failed'
    }

    $tail = @($args)
    if ($tail.Count -gt 0 -and $tail[0] -eq '--') {
        $tail = @($tail | Select-Object -Skip 1)
    }

    & $binary uninstall @tail
    exit $LASTEXITCODE
}
finally {
    Remove-Item -Recurse -Force $build -ErrorAction SilentlyContinue
}
