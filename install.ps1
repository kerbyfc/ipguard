# Install the Claude access guard (ipguard) on Windows: build from this folder and run `ipguard
# install` — install directory, binary, settings with a secret, a Task Scheduler task with a
# logon trigger and a live service probe. All the logic is in Go (`cmd/ipguard`); this script
# only builds: the folder can be zipped and handed to a colleague as is.
#
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 --yes
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -- --expected-ip <ip>
#
# The tail of the arguments goes to the Go command as is. The script has no parameters of its
# own (`param()` would make `--yes` an unknown PowerShell parameter), and PowerShell sometimes
# strips the second `--` separator itself and sometimes passes it as a string — whatever reaches
# the script is stripped below: cobra would take it as a positional argument and refuse
# (`Args: cobra.NoArgs`).
#
# A second run redoes nothing: every step prints `=` when it is already done.
$ErrorActionPreference = 'Stop'

Set-Location -Path $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error 'ipguard: Go is required — https://go.dev/dl/'
}

$build = Join-Path $env:TEMP ('ipguard-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $build | Out-Null

try {
    # GOWORK=off: the folder is its own module, and a zipped copy next to a foreign go.work does
    # not need it. -trimpath: otherwise the build path lives in the binary, and the same code
    # built from another folder gives other bytes — the "binary" step would stop being
    # idempotent.
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

    & $binary install @tail
    exit $LASTEXITCODE
}
finally {
    Remove-Item -Recurse -Force $build -ErrorAction SilentlyContinue
}
