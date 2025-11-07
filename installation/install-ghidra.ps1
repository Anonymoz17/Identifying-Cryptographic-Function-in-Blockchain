<#
Robust Windows per-user installer for Ghidra (moved to installation/).

This script installs Ghidra into a per-user default path (%LOCALAPPDATA%\Ghidra\ghidra_<version>),
verifies checksum, extracts the archive, and persists the install location into the app config using
the provided Python helper `installation/set_ghidra_config.py` when available. When Python is not available
the script falls back to a native PowerShell atomic write.

Usage examples:
  # Install from local archive and persist path (interactive license)
  .\installation\install-ghidra.ps1 -ArchivePath C:\tmp\ghidra_10.1.5.zip -Version 10.1.5 -Sha256 <hex>
<#
Canonical Windows per-user installer for Ghidra.

This script installs Ghidra into a per-user default path (%LOCALAPPDATA%\Ghidra\ghidra_<version>),
verifies SHA256 when provided, extracts the archive, and persists the install location into
%APPDATA%\cryptoscope\config.json using the Python helper if available, otherwise using a
safe PowerShell atomic write.

Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\installation\install-ghidra.ps1 -ArchivePath C:\path\ghidra.zip -Sha256 <hex> -AcceptLicense -Version 10.1.5

Options:
 -ArchivePath: local zip to install from
 -DownloadUrl: download if archive not provided
 -Sha256: expected SHA256 hex (recommended when downloading)
 -AcceptLicense: skip interactive license prompt
 -Force: overwrite existing install
 -ForceFallback: skip python helper and use PowerShell persistence
 -Uninstall: remove installed folder and persisted config
#>

[CmdletBinding()]
param(
    [string]$Version = "10.1.5",
    [string]$ArchivePath = $null,
    [string]$DownloadUrl = $null,
    [string]$Sha256 = $null,
    [switch]$AcceptLicense,
    [switch]$Force,
    [switch]$ForceFallback,
    [switch]$Uninstall
)

function Write-Log { param([string]$m) $ts = (Get-Date).ToString("s"); Write-Host "[$ts] $m" }

function Persist-GhidraInstallDir([string]$installDir, [switch]$ForceFallback) {
    Write-Log "Persisting ghidra.install_dir to app config"
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) { if ($MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path } }
    if (-not $scriptDir) { $scriptDir = Get-Location }
    $helper = Join-Path $scriptDir "set_ghidra_config.py"

    if (-not $ForceFallback -and (Test-Path $helper)) {
        $pyCandidates = @("python","python3","py")
        foreach ($py in $pyCandidates) {
            try { & $py $helper --set "$installDir"; if ($LASTEXITCODE -eq 0) { Write-Log "Persisted via python ($py)"; return $true } } catch { }
        }
    }

    try {
        $appdata = $env:APPDATA; if (-not $appdata) { throw "APPDATA not defined" }
        $cfgDir = Join-Path $appdata "cryptoscope"; New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
        $cfgPath = Join-Path $cfgDir "config.json"
        $cfgHash = @{}
        if (Test-Path $cfgPath) {
            try { $text = Get-Content -Raw -Path $cfgPath -Encoding UTF8; if ($text.Trim().Length -gt 0) { $obj = ConvertFrom-Json $text; foreach ($p in $obj.PSObject.Properties) { $cfgHash[$p.Name] = $p.Value } } } catch { $cfgHash = @{} }
        }
        if (-not $cfgHash.ContainsKey('ghidra')) { $cfgHash['ghidra'] = @{} }
        $cfgHash['ghidra']['install_dir'] = $installDir
        $json = $cfgHash | ConvertTo-Json -Depth 10
        $tmp = Join-Path $cfgDir ("config.json.tmp." + [Guid]::NewGuid().ToString())
        Set-Content -Path $tmp -Value $json -Encoding UTF8; Move-Item -Force -Path $tmp -Destination $cfgPath
        Write-Log "Persisted install path to $cfgPath"; return $true
    } catch { Write-Log "Failed to persist config via PowerShell: $_"; return $false }
}

function Unset-GhidraInstallDir() {
    Write-Log "Removing persisted ghidra.install_dir from app config"
    try {
        $appdata = $env:APPDATA; if (-not $appdata) { Write-Log "APPDATA not defined"; return }
        $cfgPath = Join-Path $appdata "cryptoscope\config.json"; if (-not (Test-Path $cfgPath)) { Write-Log "No config"; return }
        $text = Get-Content -Raw -Path $cfgPath -Encoding UTF8; $obj = ConvertFrom-Json $text
        $hash = @{}; foreach ($p in $obj.PSObject.Properties) { $hash[$p.Name] = $p.Value }
        if ($hash.ContainsKey('ghidra')) { $hash.Remove('ghidra') | Out-Null }
        $json = $hash | ConvertTo-Json -Depth 10; Set-Content -Path $cfgPath -Value $json -Encoding UTF8
        Write-Log "Removed ghidra key from $cfgPath"
    } catch { Write-Log "Failed to unset ghidra config: $_" }
}

$localApp = $env:LOCALAPPDATA; if (-not $localApp) { $localApp = "$env:USERPROFILE\AppData\Local" }
$installBase = Join-Path $localApp "Ghidra"; $installDir = Join-Path $installBase ("ghidra_" + $Version)

if ($Uninstall) {
    Write-Log "Uninstall requested. Removing $installDir if present."; if (Test-Path $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force }
    Unset-GhidraInstallDir; exit 0
}

if (-not $AcceptLicense) { Write-Host "Ghidra license: https://ghidra-sre.org/"; $ans = Read-Host "Accept license? (y/N)"; if ($ans -ne 'y' -and $ans -ne 'Y') { Write-Log "License not accepted"; exit 1 } }

$workDir = Join-Path $env:TEMP ("ghidra_install_" + [Guid]::NewGuid().ToString()); New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    if ($ArchivePath) { if (-not (Test-Path $ArchivePath)) { Write-Log "Archive not found"; exit 2 } ; Copy-Item -LiteralPath $ArchivePath -Destination (Join-Path $workDir (Split-Path $ArchivePath -Leaf)) -Force; $archiveTarget = Join-Path $workDir (Split-Path $ArchivePath -Leaf) }
    elseif ($DownloadUrl) { if (-not $Sha256) { Write-Log "Provide -Sha256 when downloading"; exit 2 } ; $fname = [System.IO.Path]::GetFileName($DownloadUrl); $out = Join-Path $workDir $fname; Invoke-WebRequest -Uri $DownloadUrl -OutFile $out -UseBasicParsing; $archiveTarget = $out }
    else { $defaultUrl = "https://ghidra-sre.org/ghidra_${Version}_PUBLIC.zip"; $out = Join-Path $workDir ([System.IO.Path]::GetFileName($defaultUrl)); Invoke-WebRequest -Uri $defaultUrl -OutFile $out -UseBasicParsing; $archiveTarget = $out }

    if ($Sha256) { $h = Get-FileHash -Algorithm SHA256 -Path $archiveTarget; if ($h.Hash.ToLower() -ne $Sha256.ToLower()) { Write-Log "SHA mismatch"; exit 3 } }
    $extractDir = Join-Path $workDir "extract"; New-Item -ItemType Directory -Path $extractDir | Out-Null; Expand-Archive -LiteralPath $archiveTarget -DestinationPath $extractDir -Force
    $children = @(Get-ChildItem -Path $extractDir | Where-Object { $_.PSIsContainer }); if ($children.Count -eq 1) { $candidate = $children[0].FullName } else { $candidate = $extractDir }
    if (Test-Path $installDir) { if ($Force) { Remove-Item -LiteralPath $installDir -Recurse -Force } else { Move-Item -LiteralPath $installDir -Destination ($installDir + ".backup_" + (Get-Date -Format yyyyMMddHHmmss)) } } else { New-Item -ItemType Directory -Path (Split-Path $installDir -Parent) -Force | Out-Null }
    Move-Item -LiteralPath $candidate -Destination $installDir -Force
    if (-not (Persist-GhidraInstallDir $installDir -ForceFallback:$ForceFallback)) { Write-Log "Warning: persist failed" }
    Write-Log "Ghidra installation completed to $installDir"; exit 0
} finally { try { Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue } catch { } }
if (-not $AcceptLicense) {
    Write-Host "Ghidra is distributed under the NCSA license: https://ghidra-sre.org/"
    $ans = Read-Host "Do you accept the license and wish to continue? (y/N)"
    if ($ans -ne 'y' -and $ans -ne 'Y') { Write-Log "License not accepted. Aborting."; exit 1 }
}

$workDir = Join-Path $env:TEMP ("ghidra_install_" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $workDir | Out-Null
$archiveTarget = $null

try {
    if ($ArchivePath) {
        if (-not (Test-Path $ArchivePath)) { Write-Log "Archive not found: $ArchivePath"; exit 2 }
        Copy-Item -LiteralPath $ArchivePath -Destination (Join-Path $workDir (Split-Path $ArchivePath -Leaf)) -Force
        $archiveTarget = Join-Path $workDir (Split-Path $ArchivePath -Leaf)
    } elseif ($DownloadUrl) {
        if (-not $Sha256) { Write-Log "DownloadUrl provided but no Sha256 given. For security, provide -Sha256. Aborting."; exit 2 }
        $fname = [System.IO.Path]::GetFileName($DownloadUrl)
        $out = Join-Path $workDir $fname
        Write-Log "Downloading $DownloadUrl to $out"
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $out -UseBasicParsing
        $archiveTarget = $out
    } else {
        # Auto-select canonical Ghidra download URL based on version
        $defaultUrl = "https://ghidra-sre.org/ghidra_${Version}_PUBLIC.zip"
        Write-Log "No ArchivePath or DownloadUrl provided. Falling back to canonical URL: $defaultUrl"
        $DownloadUrl = $defaultUrl

        $fname = [System.IO.Path]::GetFileName($DownloadUrl)
        $out = Join-Path $workDir $fname
        Write-Log "Downloading $DownloadUrl to $out"
        try {
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $out -UseBasicParsing -ErrorAction Stop
            $archiveTarget = $out
        } catch {
            Write-Log "Download failed: $_"
            exit 2
        }
    }

    # If no SHA256 provided, attempt to fetch an official checksum from likely sources
    if (-not $Sha256) {
        Write-Log "No SHA256 provided; attempting to fetch official checksum for version $Version"
        $candidates = @(
            "https://ghidra-sre.org/ghidra_${Version}_PUBLIC.zip.sha256",
            "https://ghidra-sre.org/ghidra_${Version}_PUBLIC.sha256",
            # GitHub releases sometimes host checksums in release notes or assets; try common pattern
            "https://github.com/NationalSecurityAgency/ghidra/releases/download/ghidra_${Version}_PUBLIC/ghidra_${Version}_PUBLIC.zip.sha256"
        )
        foreach ($u in $candidates) {
            try {
                Write-Log "Attempting to fetch checksum from $u"
                $resp = Invoke-WebRequest -Uri $u -UseBasicParsing -ErrorAction Stop
                $text = $resp.Content.Trim()
                # extract first 64-hex-looking token
                if ($text -match "([A-Fa-f0-9]{64})") { $Sha256 = $matches[1].ToLower(); Write-Log "Fetched SHA256: $Sha256"; break }
                # sometimes file contains checksum and filename
                if ($text -match "^([A-Fa-f0-9]{64})\s+") { $Sha256 = $matches[1].ToLower(); Write-Log "Fetched SHA256: $Sha256"; break }
            } catch {
                # ignore and continue
            }
        }
        if (-not $Sha256) { Write-Log "Unable to auto-fetch checksum for version $Version; continuing without checksum (not recommended)" }
    }

    if ($Sha256) {
        Write-Log "Verifying SHA256 of $archiveTarget"
        $h = Get-FileHash -Algorithm SHA256 -Path $archiveTarget
        $got = $h.Hash.ToLower()
        if ($got -ne $Sha256.ToLower()) { Write-Log "SHA256 mismatch: expected $Sha256 got $got"; exit 3 }
        Write-Log "Checksum OK"
    } else { Write-Log "No SHA256 provided - skipping verification (not recommended)" }

    $extractDir = Join-Path $workDir "extract"
    New-Item -ItemType Directory -Path $extractDir | Out-Null
    Write-Log "Extracting archive to $extractDir"
    try { Expand-Archive -LiteralPath $archiveTarget -DestinationPath $extractDir -Force } catch { Write-Log "Extraction failed: $_"; exit 4 }

    $children = @(Get-ChildItem -Path $extractDir | Where-Object { $_.PSIsContainer })
    if ($children.Count -eq 1) { $candidate = $children[0].FullName } else { $candidate = $extractDir }

    if (Test-Path $installDir) {
        if ($Force) { Write-Log "Force requested; removing existing $installDir"; Remove-Item -LiteralPath $installDir -Recurse -Force }
        else { $backup = $installDir + ".backup_" + (Get-Date -Format yyyyMMddHHmmss); Write-Log "Existing install detected; moving to $backup"; Move-Item -LiteralPath $installDir -Destination $backup }
    } else { New-Item -ItemType Directory -Path (Split-Path $installDir -Parent) -Force | Out-Null }

    Write-Log "Moving $candidate to $installDir"
    Move-Item -LiteralPath $candidate -Destination $installDir -Force

    $analyzeCandidates = @( (Join-Path $installDir "support\analyzeHeadless.bat"), (Join-Path $installDir "analyzeHeadless.bat") )
    $found = $false
    foreach ($p in $analyzeCandidates) { if (Test-Path $p) { $found = $true; $analyzePath = $p; break } }
    if (-not $found) {
        Write-Log "Warning: analyzeHeadless not found in install - installation may be incomplete"
    } else {
        Write-Log "Found analyzeHeadless at $analyzePath"
    }

    Write-Log "Persisting install path to app config"
    # Use Persist-GhidraInstallDir which will try the Python helper first and fall back to native PowerShell
    if (-not (Persist-GhidraInstallDir $installDir -ForceFallback:$ForceFallback)) { Write-Log "Warning: failed to persist install dir via helper and PowerShell fallback" }

    Write-Log "Ghidra installation completed to $installDir"
    exit 0
} finally {
    try { Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}
