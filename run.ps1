<#
.SYNOPSIS
    Launch CryptoScope application

.DESCRIPTION
    Activates the virtual environment and runs the CryptoScope GUI app (src/app.py)
    from the project root directory.

.EXAMPLE
    .\run.ps1
#>

param()

# Get script directory (project root)
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $repoRoot) { $repoRoot = Get-Location }

$venvPath = Join-Path $repoRoot ".venv"
$pythonExe = Join-Path $venvPath "Scripts\python.exe"
$appPy = Join-Path $repoRoot "src\app.py"

# Validate venv exists
if (-not (Test-Path $pythonExe)) {
    Write-Host "[ERROR] Virtual environment not found at $venvPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please run the installer first:" -ForegroundColor Yellow
    Write-Host "  .\install.ps1" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Validate app.py exists
if (-not (Test-Path $appPy)) {
    Write-Host "[ERROR] app.py not found at $appPy" -ForegroundColor Red
    exit 1
}

# Launch the app
Write-Host "[INFO] Launching CryptoScope..." -ForegroundColor Cyan
Write-Host ""

& $pythonExe $appPy

exit $LASTEXITCODE
