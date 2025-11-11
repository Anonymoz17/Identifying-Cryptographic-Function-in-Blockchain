<#
Robust Windows per-user installer for Ghidra (clean copy).
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
