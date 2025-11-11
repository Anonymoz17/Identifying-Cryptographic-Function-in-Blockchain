<#
.SYNOPSIS
Developer helper to point the current PowerShell session at a local Ghidra install and run the project's verification helper.

.DESCRIPTION
This script is for developers only. It sets the `GHIDRA_INSTALL_DIR` environment variable for the current session, checks that
`support\analyzeHeadless.bat` exists under the provided install directory, and invokes the repository's small Python verifier
to print the resolved AnalyzeHeadless path and a short verification output.

It does NOT modify system-wide environment variables unless you explicitly call `setx` yourself or use the `-Save` switch.

.PARAMETER InstallDir
Path to the Ghidra top-level directory (the folder that contains `ghidraRun.bat` and the `support` subfolder).

.PARAMETER Save
Optional switch. If supplied, the script will write the install dir into the project's per-user config using the internal
Python helper. This persists the path for the application (doesn't modify global env vars).

.PARAMETER RunVerify
Optional switch. If supplied (default), runs the repository's verify helper which attempts to run a small probe against
`analyzeHeadless` and prints results.

EXAMPLE
.
    .\tools\ghidra-dev-setup.ps1 -InstallDir 'C:\Users\You\Desktop\ghidra_11.4.2_PUBLIC' -Save

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$InstallDir,
    [switch]$Save,
    [switch]$RunVerify = $true
)

function Write-Info($s) { Write-Host "[ghidra-dev-setup] $s" -ForegroundColor Cyan }
function Write-Err($s) { Write-Host "[ghidra-dev-setup] $s" -ForegroundColor Red }

if (-not (Test-Path $InstallDir)) {
    Write-Err "InstallDir '$InstallDir' not found. Provide the top-level Ghidra folder path."; exit 2
}

$supportBat = Join-Path $InstallDir 'support\analyzeHeadless.bat'
if (-not (Test-Path $supportBat)) {
    Write-Warning "Could not find 'support\\analyzeHeadless.bat' under the provided path. The folder you provided may still be correct if you downloaded a different layout; double-check the path."
    Write-Host "Looking for 'analyzeHeadless' without extension as well..."
    $supportNoExt = Join-Path $InstallDir 'support\analyzeHeadless'
    if (-not (Test-Path $supportNoExt)) {
        Write-Err "No analyzeHeadless found under '$InstallDir\support'. The headless adapter expects analyzeHeadless.bat (Windows)."; exit 3
    }
}

Write-Info "Setting GHIDRA_INSTALL_DIR for this session to: $InstallDir"
$env:GHIDRA_INSTALL_DIR = $InstallDir

if ($RunVerify) {
    Write-Info "Running repository verify helper (will print ANALYZE_PATH and VERIFY)..."
    $py = 'import sys; sys.path.insert(0,\"src\"); from auditor.detectors.static_detection import ghidra_adapter; p=ghidra_adapter.resolve_ghidra(); v=ghidra_adapter.verify_ghidra(p) if p else None; print(\"ANALYZE_PATH:\", p); print(\"VERIFY:\", v)'
    python -c $py
}

if ($Save) {
    Write-Info "Persisting the install dir into the project's per-user config..."
    $pySave = 'import sys; sys.path.insert(0,\"src\"); from auditor.detectors.static_detection import config; config.set_ghidra_install_dir(r"' + $InstallDir + '"); print(\"saved\")'
    python -c $pySave
    if ($LASTEXITCODE -eq 0) { Write-Info "Saved to project config." } else { Write-Err "Save failed (python exit code $LASTEXITCODE)." }
}

Write-Info "Done. The environment variable is set only for this session. To make it permanent for your user, run:`setx GHIDRA_INSTALL_DIR \"$InstallDir\"` and restart PowerShell.`"
