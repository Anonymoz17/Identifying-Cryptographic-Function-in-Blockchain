<#
.SYNOPSIS
    First-time setup for CryptoScope

.DESCRIPTION
    Runs the complete setup process:
    1. Installs Python dependencies via install.ps1
    2. Launches the application via run.ps1

    After first setup, you can run the app directly with run.ps1

.PARAMETER SkipGhidra
    Skip Ghidra installation

.PARAMETER Force
    Force reinstall of dependencies

.EXAMPLE
    .\setup.ps1
#>

[CmdletBinding()]
param(
    [switch]$SkipGhidra,
    [switch]$Force
)

$repoRoot = $PSScriptRoot
if (-not $repoRoot) { $repoRoot = Get-Location }

Write-Host ""
Write-Host "CryptoScope - First-Time Setup" -ForegroundColor Cyan
Write-Host ""

$installArgs = @()
if ($SkipGhidra) { $installArgs += "-SkipGhidra" }
if ($Force) { $installArgs += "-Force" }

Write-Host "Step 1: Running installation script..." -ForegroundColor Yellow
Write-Host ""

$installScript = Join-Path $repoRoot "install.ps1"
& $installScript @installArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Installation failed. Please fix errors above." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Step 2: Launching CryptoScope..." -ForegroundColor Yellow
Write-Host ""

$runScript = Join-Path $repoRoot "run.ps1"
& $runScript
$exitCode = $LASTEXITCODE

Write-Host ""
Write-Host "CryptoScope closed." -ForegroundColor Cyan
Write-Host ""
Write-Host "To run CryptoScope next time, use:" -ForegroundColor Green
Write-Host "  run.ps1" -ForegroundColor Green
Write-Host ""

exit $exitCode
