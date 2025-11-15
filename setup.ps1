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

# Validate required files
Write-Host "Validating project files..." -ForegroundColor Yellow
$requiredFiles = @(
    "install.ps1",
    "run.ps1",
    "requirements.txt",
    "src\app.py"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    $filePath = Join-Path $repoRoot $file
    if (-not (Test-Path $filePath)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host ""
    Write-Host "ERROR: Missing required files:" -ForegroundColor Red
    foreach ($file in $missingFiles) {
        Write-Host "  - $file" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "This may indicate:" -ForegroundColor Yellow
    Write-Host "  1. Incomplete download or extraction" -ForegroundColor Yellow
    Write-Host "  2. Files were deleted or moved" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please download the complete project from:" -ForegroundColor Cyan
    Write-Host "  https://github.com/Anonymoz17/Identifying-Cryptographic-Function-in-Blockchain" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

Write-Host "Project files validated" -ForegroundColor Green
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
