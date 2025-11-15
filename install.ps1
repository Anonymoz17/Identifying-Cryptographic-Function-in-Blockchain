<#
.SYNOPSIS
    Unified Windows installation script for CryptoScope

.DESCRIPTION
    One-stop setup for CryptoScope that:
    1. Validates Python 3.10-3.13
    2. Creates virtual environment
    3. Installs Python dependencies
    4. Downloads and sets up Ghidra
    5. Validates the complete installation

.PARAMETER SkipGhidra
    Skip Ghidra installation (Python-only setup)

.PARAMETER Force
    Force overwrite of existing installations

.PARAMETER GhidraVersion
    Ghidra version to install (default: 10.1.5)

.EXAMPLE
    .\install.ps1                          # Full setup
    .\install.ps1 -SkipGhidra              # Python deps only
    .\install.ps1 -Force                   # Force reinstall
#>

[CmdletBinding()]
param(
    [switch]$SkipGhidra,
    [switch]$Force,
    [string]$GhidraVersion = "10.1.5"
)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = "[$timestamp]"

    switch ($Level) {
        "ERROR"   { Write-Host "$prefix [ERROR] $Message" -ForegroundColor Red }
        "WARN"    { Write-Host "$prefix [WARN]  $Message" -ForegroundColor Yellow }
        "SUCCESS" { Write-Host "$prefix [OK]    $Message" -ForegroundColor Green }
        default   { Write-Host "$prefix [INFO]  $Message" }
    }
}

function Test-CommandExists {
    param([string]$Command)
    $null = Get-Command $Command -ErrorAction SilentlyContinue
    return $?
}

function Exit-WithError {
    param([string]$Message, [int]$Code = 1)
    Write-Log $Message "ERROR"
    exit $Code
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Log "Running as Administrator" "WARN"
    Write-Log ""
    Write-Log "WARNING: It is recommended to run this script as a regular user, not as Administrator." "WARN"
    Write-Log ""
    Write-Log "Running as admin may cause permission issues when launching the application later." "WARN"
    Write-Log "Please close this window and run 'setup.ps1' or 'install.ps1' as your regular user account." "WARN"
    Write-Log ""

    $response = Read-Host "Press Enter to continue anyway, or type 'exit' to cancel"
    if ($response -eq "exit") {
        Write-Log "Cancelled by user" "WARN"
        exit 0
    }
    Write-Log ""
}

Write-Log "Step 1: Validating Python installation..."

$pythonCmd = $null
foreach ($candidate in @("python", "python3", "py")) {
    if (Test-CommandExists $candidate) {
        $pythonCmd = $candidate
        break
    }
}

if (-not $pythonCmd) {
    Exit-WithError "Python not found on PATH. Please install Python 3.10-3.13 and ensure it is added to PATH."
}

Write-Log "Found Python: $pythonCmd"

$versionOutput = & $pythonCmd --version 2>&1
$versionMatch = $versionOutput -match "(\d+\.\d+)"
if (-not $versionMatch) {
    Exit-WithError "Could not determine Python version"
}

$pyVersion = [version]$matches[1]
Write-Log "Python version: $pyVersion"

if ($pyVersion -lt [version]"3.10" -or $pyVersion -ge [version]"3.14") {
    Exit-WithError "Python 3.10-3.13 required. Current: $pyVersion"
}

Write-Log "Python version OK" "SUCCESS"

Write-Log "Step 2: Setting up virtual environment..."

$repoRoot = $PSScriptRoot
if (-not $repoRoot) { $repoRoot = Get-Location }

$venvPath = Join-Path $repoRoot ".venv"

if (Test-Path $venvPath) {
    if ($Force) {
        Write-Log "Removing existing venv..."
        try {
            Remove-Item -LiteralPath $venvPath -Recurse -Force -ErrorAction Stop
            Write-Log "venv deleted successfully" "SUCCESS"
        } catch {
            Exit-WithError "Failed to delete existing venv. Try closing terminals or run with admin privileges."
        }
    } else {
        Write-Log "Virtual environment already exists at $venvPath" "SUCCESS"
        Write-Log "Use -Force flag to reinstall: .\install.ps1 -Force"
    }
}

if (-not (Test-Path $venvPath)) {
    Write-Log "Creating virtual environment..."
    & $pythonCmd -m venv $venvPath
    if ($LASTEXITCODE -ne 0) {
        Exit-WithError "Failed to create virtual environment"
    }
}

Write-Log "Virtual environment ready" "SUCCESS"

$pipPath = Join-Path $venvPath "Scripts\pip.exe"
if (-not (Test-Path $pipPath)) {
    Exit-WithError "pip not found in venv at $pipPath"
}

Write-Log "Step 3: Installing Python dependencies..."

$requirementsPath = Join-Path $repoRoot "requirements.txt"
if (-not (Test-Path $requirementsPath)) {
    Exit-WithError "requirements.txt not found at $requirementsPath"
}

Write-Log "Installing packages from $requirementsPath..."
& $pipPath install -q --no-cache-dir -r $requirementsPath
if ($LASTEXITCODE -ne 0) {
    Write-Log "Retrying without cache optimization..."
    & $pipPath install -r $requirementsPath
    if ($LASTEXITCODE -ne 0) {
        Exit-WithError "Failed to install Python dependencies"
    }
}

Write-Log "Python dependencies installed" "SUCCESS"

if ($SkipGhidra) {
    Write-Log "Skipping Ghidra setup (--SkipGhidra)"
} else {
    Write-Log "Step 4: Setting up Ghidra..."

    $localApp = $env:LOCALAPPDATA
    if (-not $localApp) { $localApp = "$env:USERPROFILE\AppData\Local" }

    $ghidraBase = Join-Path $localApp "Ghidra"
    $ghidraInstallDir = Join-Path $ghidraBase ("ghidra_" + $GhidraVersion)

    $ghidraAnalyzer = @(
        (Join-Path $ghidraInstallDir "support\analyzeHeadless.bat"),
        (Join-Path $ghidraInstallDir "analyzeHeadless.bat")
    ) | Where-Object { Test-Path $_ }

    if ($ghidraAnalyzer -and -not $Force) {
        Write-Log "Ghidra $GhidraVersion already installed at $ghidraInstallDir" "SUCCESS"
    } else {
        Write-Log "Downloading Ghidra $GhidraVersion..."

        $tempDir = Join-Path $env:TEMP ("ghidra_install_" + [Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tempDir | Out-Null

        try {
            $downloadUrl = "https://ghidra-sre.org/ghidra_${GhidraVersion}_PUBLIC.zip"
            $zipFile = Join-Path $tempDir "ghidra.zip"

            Write-Log "Downloading from $downloadUrl..."
            Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile -UseBasicParsing -ErrorAction Stop
            Write-Log "Download complete" "SUCCESS"

            $extractDir = Join-Path $tempDir "extract"
            New-Item -ItemType Directory -Path $extractDir | Out-Null

            Write-Log "Extracting archive..."
            try {
                Expand-Archive -LiteralPath $zipFile -DestinationPath $extractDir -Force -ErrorAction Stop
            } catch {
                Write-Log "Failed to extract with Expand-Archive, attempting workaround..." "WARN"
                Write-Log "Using alternative extraction method..."

                # Fallback: Try using .NET compression directly
                try {
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $extractDir, $true)
                } catch {
                    Exit-WithError "Failed to extract Ghidra archive: $($_.Exception.Message). The downloaded file may be corrupted. Try again or download manually from https://ghidra-sre.org/"
                }
            }

            $children = @(Get-ChildItem -Path $extractDir -Directory)
            if ($children.Count -eq 1) {
                $extractedDir = $children[0].FullName
            } else {
                $extractedDir = $extractDir
            }

            if (Test-Path $ghidraInstallDir) {
                if ($Force) {
                    Write-Log "Force remove existing installation..."
                    Remove-Item -LiteralPath $ghidraInstallDir -Recurse -Force
                } else {
                    $backup = $ghidraInstallDir + ".backup_" + (Get-Date -Format yyyyMMddHHmmss)
                    Write-Log "Backing up existing installation to $backup..."
                    Move-Item -LiteralPath $ghidraInstallDir -Destination $backup
                }
            } else {
                New-Item -ItemType Directory -Path $ghidraBase -Force | Out-Null
            }

            Write-Log "Installing Ghidra to $ghidraInstallDir..."
            Move-Item -LiteralPath $extractedDir -Destination $ghidraInstallDir -Force

            $analyzerPath = @(
                (Join-Path $ghidraInstallDir "support\analyzeHeadless.bat"),
                (Join-Path $ghidraInstallDir "analyzeHeadless.bat")
            ) | Where-Object { Test-Path $_ } | Select-Object -First 1

            if ($analyzerPath) {
                Write-Log "Ghidra installed successfully" "SUCCESS"
                Write-Log "Analyzer found at: $analyzerPath"
            } else {
                Write-Log "Warning: analyzeHeadless not found (installation may be incomplete)" "WARN"
            }

            Persist-GhidraConfig $ghidraInstallDir

        } finally {
            if (Test-Path $tempDir) {
                Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Write-Log "Step 5: Validating installation..."

$appPyPath = Join-Path $repoRoot "src\app.py"
if (-not (Test-Path $appPyPath)) {
    Exit-WithError "app.py not found at $appPyPath"
}

$pythonExe = Join-Path $venvPath "Scripts\python.exe"
& $pythonExe -c "import customtkinter; import supabase" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Exit-WithError "Failed to import required modules. Check requirements.txt"
}

Write-Log "All dependencies validated" "SUCCESS"

Write-Log ""
Write-Log "Installation Complete!" -Level "SUCCESS"
Write-Log ""
Write-Log "Next step: Run the application with:"
Write-Log ""
Write-Log "  .\run.ps1"
Write-Log ""

exit 0

function Persist-GhidraConfig {
    param([string]$GhidraPath)

    try {
        $appdata = $env:APPDATA
        if (-not $appdata) {
            Write-Log "Cannot persist config: APPDATA not set" "WARN"
            return
        }

        $configDir = Join-Path $appdata "cryptoscope"
        $configPath = Join-Path $configDir "config.json"

        New-Item -ItemType Directory -Path $configDir -Force | Out-Null

        $config = @{ ghidra = @{ install_dir = $GhidraPath } }

        if (Test-Path $configPath) {
            try {
                $existing = Get-Content -Raw -Path $configPath -Encoding UTF8 | ConvertFrom-Json
                if ($existing) {
                    $config = $existing | ConvertTo-Json -Depth 10 | ConvertFrom-Json
                    $config.ghidra = @{ install_dir = $GhidraPath }
                }
            } catch {
                Write-Log "Could not merge with existing config" "WARN"
            }
        }

        $json = $config | ConvertTo-Json -Depth 10
        $tempFile = Join-Path $configDir ("config.json.tmp." + [Guid]::NewGuid().ToString())
        Set-Content -Path $tempFile -Value $json -Encoding UTF8
        Move-Item -Force -Path $tempFile -Destination $configPath

        Write-Log "Ghidra config saved to $configPath"
    } catch {
        Write-Log "Warning: Could not save Ghidra config" "WARN"
    }
}
