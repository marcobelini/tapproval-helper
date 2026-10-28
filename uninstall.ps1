# Tapproval Base uninstaller for Windows: a clean exit, announced first.
#
#   irm https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/uninstall.ps1 | iex
#
# uninstall.sh's twin for PowerShell (2026-10-28). Windows has no iCloud
# bridge, so there is nothing of the Mac's to stop.
$ErrorActionPreference = "Continue"

Write-Host "Tapproval Base uninstaller - here is everything it will do:"
Write-Host "  1. Remove Base's hooks and settings entries (a settings backup is kept)"
Write-Host "  2. Stop the local relay and its travel tunnel"
Write-Host "  3. Delete ~\.tapproval (the helper, its data and its logs)"
Write-Host "  4. Forget the paired watch (its key is in ~\.tapproval\data)"
Write-Host "     - after a reinstall, pair it again from Settings"
Write-Host "  Your audit log stays, so your own history remains yours."
Write-Host ""

$Dir = Join-Path $HOME ".tapproval"
$Hook = Join-Path $Dir "ClaudeRiskClassifier.py"

function Find-Python {
    foreach ($candidate in @(@("py", "-3"), @("python"), @("python3"))) {
        $exe = Get-Command $candidate[0] -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        $rest = @($candidate | Select-Object -Skip 1)
        $path = & $exe.Source @rest -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $path) { return $path.Trim() }
    }
    return $null
}

if (Test-Path $Hook) {
    $Python = Find-Python
    if ($Python) {
        & $Python $Hook --uninstall
        if ($LASTEXITCODE -ne 0) { Write-Host "(continuing: the rest is removed either way)" }
    } else {
        Write-Host "(no Python found - the hooks stay in settings.json; remove them by hand)"
    }
} else {
    Write-Host "(~\.tapproval not found - nothing registered to remove)"
}

# This install's relay, by the pid it wrote, never every relay this user runs.
$PidFile = Join-Path $Dir "data\relay.pid"
if (Test-Path $PidFile) {
    $RelayPid = (Get-Content $PidFile -Raw) -replace "[^0-9]", ""
    if ($RelayPid) {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $RelayPid" -ErrorAction SilentlyContinue
        if ($proc -and $proc.CommandLine -like "*watch_relay.py*") {
            Stop-Process -Id $RelayPid -Force -ErrorAction SilentlyContinue
        }
    }
}
# The travel tunnel outlives a relay on purpose; an uninstall must stop it,
# or a public URL would outlive Tapproval.
Get-CimInstance Win32_Process -Filter "Name = 'cloudflared.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*127.0.0.1:8978*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

if (Test-Path $Dir) { Remove-Item -Recurse -Force $Dir -ErrorAction SilentlyContinue }
Get-ChildItem -Path $HOME -Directory -Filter ".tapproval.superseded-*" -Force -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $HOME -Directory -Filter ".tapproval.fresh-*" -Force -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "TAPPROVAL_BASE_REMOVED"
