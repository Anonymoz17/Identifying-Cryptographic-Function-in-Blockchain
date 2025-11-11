<#
Robust Windows per-user installer for Ghidra.

This script installs Ghidra into a per-user default path (%LOCALAPPDATA%\Ghidra\ghidra_<version>),
verifies checksum, extracts the archive, and persists the install location into the app config using
the provided Python helper `tools/set_ghidra_config.py`.

Usage examples:
  # Install from local archive and persist path (interactive license)
  .\tools\install-ghidra.ps1 -ArchivePath C:\tmp\ghidra_10.1.5.zip -Version 10.1.5 -Sha256 <hex>

  # Non-interactive (CI): must provide -AcceptLicense and -Sha256
  .\tools\install-ghidra.ps1 -DownloadUrl https://example/ghidra.zip -Sha256 <hex> -AcceptLicense

  # Uninstall
  .\tools\install-ghidra.ps1 -Uninstall

Note: For security always provide -Sha256 when downloading. For offline installs, provide -ArchivePath.
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

# Persist/install helper: try python helper first, fallback to native PowerShell write
function Persist-GhidraInstallDir([string]$installDir, [switch]$ForceFallback) {
    Write-Log "Persisting ghidra.install_dir to app config"

    # If ForceFallback is not set, try to use the Python helper first
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) {
        if ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
    }
    if (-not $scriptDir) { $scriptDir = Get-Location }
    $helper = Join-Path $scriptDir "set_ghidra_config.py"

    if (-not $ForceFallback) {
        if (Test-Path $helper) {
            $pyCandidates = @("python", "python3", "py")
            foreach ($pyCmd in $pyCandidates) {
                try {
                    Write-Log "Trying python helper with $pyCmd"
                    & $pyCmd $helper --set "$installDir" 2>&1 | Write-Host
                    if ($LASTEXITCODE -eq 0) { Write-Log "Persisted via python helper ($pyCmd)"; return $true }
                } catch { }
            }
            Write-Log "Python helper found but no python launcher succeeded; falling back to native PowerShell write"
        }
    } else {
        Write-Log "ForceFallback requested; skipping python helper and using native PowerShell write"
    }

    try {
        $appdata = $env:APPDATA
        if (-not $appdata) { throw "APPDATA not defined" }
        $cfgDir = Join-Path $appdata "cryptoscope"
        New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
        $cfgPath = Join-Path $cfgDir "config.json"

        $cfgHash = @{}
        if (Test-Path $cfgPath) {
            try {
                $text = Get-Content -Raw -Path $cfgPath -Encoding UTF8
                if ($text -and $text.Trim().Length -gt 0) {
                    $obj = ConvertFrom-Json $text -ErrorAction Stop
                    try {
                        foreach ($p in $obj.PSObject.Properties) { $cfgHash[$p.Name] = $p.Value }
                    ```powershell
                    # Legacy shim: tools/install-ghidra.ps1
                    # The canonical installer was moved to installation/install-ghidra.ps1. This shim prints a deprecation
                    # notice and forwards all arguments to the new installer to preserve backward compatibility.

                    param(
                        [Parameter(ValueFromRemainingArguments=$true)]
                        $RemainingArgs
                    )

                    Write-Host "tools/install-ghidra.ps1 is deprecated; using installation/install-ghidra.ps1 instead"

                    $script = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) "..\installation\install-ghidra.ps1"
                    $script = (Resolve-Path $script).ProviderPath

                    # Reconstruct the argument string safely
                    $argString = $RemainingArgs -join ' '

                    & "$script" $RemainingArgs

                    ```
}
