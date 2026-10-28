# Tapproval helper for Windows: one-line install, nothing to keep running.
#
#   irm https://raw.githubusercontent.com/marcobelini/tapproval-helper/main/install.ps1 | iex
#
# install.sh's twin for PowerShell (2026-10-28: the helper runs on every
# host). Installs onto the computer where Claude Code runs, registers the
# risk-triage hook, and wires the relay to start itself with every Claude
# Code session. Needs Git for Windows and Python 3.9 or later; standard
# library Python only. Windows PowerShell 5.1 and PowerShell 7 alike.
$ErrorActionPreference = "Stop"

$Dir = Join-Path $HOME ".tapproval"
$Repo = "https://github.com/marcobelini/tapproval-helper.git"

function Find-Python {
    # The py launcher first: python.org's installer always brings it, and a
    # bare "python3" on Windows is often the Store's placeholder, which
    # opens the Store instead of running anything.
    foreach ($candidate in @(@("py", "-3"), @("python"), @("python3"))) {
        $exe = Get-Command $candidate[0] -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        $rest = @($candidate | Select-Object -Skip 1)
        $path = & $exe.Source @rest -c "import sys; print(sys.executable) if sys.version_info >= (3, 9) else sys.exit(1)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $path) { return $path.Trim() }
    }
    throw "Python 3.9 or later was not found. Install it from https://www.python.org/downloads/windows/ and run this again."
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git was not found. Install Git for Windows from https://git-scm.com/downloads/win and run this again."
}

if (Test-Path (Join-Path $Dir ".git")) {
    git -C $Dir pull -q --ff-only 2>$null
    if ($LASTEXITCODE -ne 0) {
        # As install.sh: a fresh clone beside it, swapped in only once whole,
        # carrying the helper's data (the paired watches' keys) and logs.
        Write-Host "update: fetching a fresh copy (the existing one could not fast-forward)"
        $fresh = "$Dir.fresh-$PID"
        if (Test-Path $fresh) { Remove-Item -Recurse -Force $fresh }
        git clone -q --depth 1 $Repo $fresh
        if ($LASTEXITCODE -eq 0) {
            $superseded = "$Dir.superseded-" + (Get-Date -Format "yyyyMMdd-HHmmss")
            try {
                foreach ($kept in @("data", "logs")) {
                    $from = Join-Path $Dir $kept
                    if (Test-Path $from) { Move-Item $from (Join-Path $fresh $kept) }
                }
                Move-Item $Dir $superseded
                Move-Item $fresh $Dir
            } catch {
                foreach ($kept in @("data", "logs")) {
                    $moved = Join-Path $fresh $kept
                    if ((Test-Path $moved) -and -not (Test-Path (Join-Path $Dir $kept))) {
                        Move-Item $moved (Join-Path $Dir $kept) -ErrorAction SilentlyContinue
                    }
                }
                if ((Test-Path $superseded) -and -not (Test-Path $Dir)) { Move-Item $superseded $Dir }
                Write-Warning "update: could not swap in the fresh copy; keeping the one installed"
            }
            if (Test-Path $fresh) { Remove-Item -Recurse -Force $fresh -ErrorAction SilentlyContinue }
        } else {
            if (Test-Path $fresh) { Remove-Item -Recurse -Force $fresh -ErrorAction SilentlyContinue }
            Write-Warning "update: could not fetch a fresh copy either; keeping the one installed"
        }
    }
} elseif (Test-Path $Dir) {
    # A folder that is not a checkout (a plugin install's data and logs):
    # made a checkout in place, keeping what is there.
    git -C $Dir init -q
    git -C $Dir remote add origin $Repo 2>$null
    if ($LASTEXITCODE -ne 0) { git -C $Dir remote set-url origin $Repo }
    git -C $Dir fetch -q --depth 1 origin main
    git -C $Dir checkout -q -f -B main --track origin/main
} else {
    git clone -q --depth 1 $Repo $Dir
    if ($LASTEXITCODE -ne 0) { throw "could not download the helper from $Repo" }
}

$Python = Find-Python
# One call: --watch wires enforce mode and the relay address, as install.sh.
& $Python (Join-Path $Dir "ClaudeRiskClassifier.py") --install --watch
if ($LASTEXITCODE -ne 0) { throw "the hook could not be installed (exit $LASTEXITCODE)" }
& $Python (Join-Path $Dir "watch_relay.py") --ensure

Write-Host ""
Write-Host "TAPPROVAL_BASE_READY"
Write-Host "OK: Tapproval Base is ready. Start a new Claude Code session,"
Write-Host "    then open Tapproval on your watch - it connects by itself."
Write-Host "    No watch app yet? https://apps.apple.com/app/tapproval/id6805869018"
Write-Host "    or the beta, where the unlock is free: https://testflight.apple.com/join/dW1tYBQG"
Write-Host "    Downloaded it but it's not on the watch? On the iPhone, open the"
Write-Host "    Watch app and tap Install under Available Apps."
