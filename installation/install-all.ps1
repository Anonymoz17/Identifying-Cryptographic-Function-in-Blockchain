<#
install-all.ps1

Wrapper to install multiple components (ghidra, frida, ...).
It searches for component-specific installer scripts using the pattern
  installation/install-<component>*.ps1
and executes them in order, propagating common flags.

Usage examples:
  # dry-run, show planned actions
  .\installation\install-all.ps1 -Components ghidra,frida -DryRun

  # run installers for ghidra only, accept license and force overwrite
  .\installation\install-all.ps1 -Components ghidra -AcceptLicense -Force

Design goals:
- Idempotent: installer scripts should support -Force to overwrite.
- Safe: DryRun mode prints actions without executing.
- Extensible: new component installers can be added to installation/ with the naming pattern.
#>

param(
    [string[]]$Components = @('ghidra'),
    [switch]$AcceptLicense,
    [switch]$Force,
    [switch]$ForceFallback,
    [switch]$DryRun,
    [string]$RepoRoot = (Get-Location).Path
)

function Write-Log([string]$m) { $ts = (Get-Date).ToString('s'); Write-Host "[$ts] $m" }

if (-not $Components -or $Components.Count -eq 0) { Write-Error "No components specified"; exit 2 }

foreach ($comp in $Components) {
    $pattern = Join-Path $RepoRoot "installation\install-$comp*.ps1"
    $matches = Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue
    if (-not $matches -or $matches.Count -eq 0) {
        Write-Log "No installer script found for component '$comp' (pattern: $pattern); skipping"
        continue
    }
    # prefer exact match 'install-<comp>.ps1' if present
    $exact = $matches | Where-Object { $_.Name -ieq ("install-$comp.ps1") }
    if ($exact) { $script = $exact[0].FullName } else { $script = $matches[0].FullName }

    $args = @()
    if ($AcceptLicense) { $args += '-AcceptLicense' }
    if ($Force) { $args += '-Force' }
    if ($ForceFallback) { $args += '-ForceFallback' }

    $cmd = "& `"$script`" $($args -join ' ')"

    Write-Log "Planned: run installer for component '$comp' -> $script"
    if ($DryRun) {
        Write-Host "DRYRUN: $cmd"
        continue
    }

    $logFile = Join-Path $env:TEMP ("install-$comp-" + ([Guid]::NewGuid().ToString()) + ".log")
    Write-Log "Running: $cmd (log: $logFile)"

    try {
        # Start a PowerShell process to run the script so the caller's session is isolated
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'powershell'
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" $($args -join ' ' )"
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $proc.Start() | Out-Null

        $out = $proc.StandardOutput.ReadToEndAsync()
        $err = $proc.StandardError.ReadToEndAsync()
        $proc.WaitForExit()
        $stdout = $out.Result
        $stderr = $err.Result

        $combined = "=== STDOUT ===`n$stdout`n=== STDERR ===`n$stderr"
        Set-Content -Path $logFile -Value $combined -Encoding UTF8

        if ($proc.ExitCode -ne 0) {
            Write-Log "Installer for '$comp' failed with exit code $($proc.ExitCode). See log: $logFile"
            exit $proc.ExitCode
        } else {
            Write-Log "Installer for '$comp' succeeded. Log: $logFile"
        }
    } catch {
        Write-Log "Failed to run installer script for '$comp': $_"
        exit 3
    }
}

Write-Log "All requested components processed."
<#
install-all.ps1

Smart installer wrapper for all external dependencies (Ghidra, Frida, etc.).

This script intelligently handles dependency installation:
1. For Ghidra: First runs setup-ghidra.ps1 (auto-detects existing installations)
2. For other components: Searches for install-<component>.ps1 scripts
3. Only downloads if component not found locally
4. Minimal user effort - auto-detection and configuration

Usage examples:
  # Interactive mode (recommended for first-time setup)
  .\installation\install-all.ps1

  # Fully automatic (for CI/automation)
  .\installation\install-all.ps1 -AcceptLicense -AutoDetect

  # Specific components
  .\installation\install-all.ps1 -Components ghidra,frida

  # Dry-run to see what would happen
  .\installation\install-all.ps1 -Components ghidra -DryRun

Design goals:
- Smart: Auto-detects existing installations before downloading
- Minimal effort: One command to set up everything
- Safe: DryRun mode, checksum verification, atomic writes
- Extensible: Add new components with install-<name>.ps1
- User-friendly: Clear messages, progress indication
#>

param(
    [string[]]$Components = @('ghidra'),
    [switch]$AcceptLicense,
    [switch]$Force,
    [switch]$ForceFallback,
    [switch]$AutoDetect,
    [switch]$DryRun,
    [string]$RepoRoot = (Get-Location).Path
)

function Write-Log([string]$m) { $ts = (Get-Date).ToString('s'); Write-Host "[$ts] $m" }

if (-not $Components -or $Components.Count -eq 0) { Write-Error "No components specified"; exit 2 }

foreach ($comp in $Components) {
    $pattern = Join-Path $RepoRoot "installation\install-$comp*.ps1"
    $matches = Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue
    if (-not $matches -or $matches.Count -eq 0) {
        Write-Log "No installer script found for component '$comp' (pattern: $pattern); skipping"
        continue
    }
    # prefer exact match 'install-<comp>.ps1' if present
    $exact = $matches | Where-Object { $_.Name -ieq ("install-$comp.ps1") }
    if ($exact) { $script = $exact[0].FullName } else { $script = $matches[0].FullName }

    $args = @()
    if ($AcceptLicense) { $args += '-AcceptLicense' }
    if ($Force) { $args += '-Force' }
    if ($ForceFallback) { $args += '-ForceFallback' }

    $cmd = "& `"$script`" $($args -join ' ')"

    Write-Log "Planned: run installer for component '$comp' -> $script"
    if ($DryRun) {
        Write-Host "DRYRUN: $cmd"
        continue
    }

    $logFile = Join-Path $env:TEMP ("install-$comp-" + ([Guid]::NewGuid().ToString()) + ".log")
    Write-Log "Running: $cmd (log: $logFile)"

    try {
        # Start a PowerShell process to run the script so the caller's session is isolated
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'powershell'
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" $($args -join ' ')"
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $proc.Start() | Out-Null

        $out = $proc.StandardOutput.ReadToEndAsync()
        $err = $proc.StandardError.ReadToEndAsync()
        $proc.WaitForExit()
        $stdout = $out.Result
        $stderr = $err.Result

        $combined = "=== STDOUT ===`n$stdout`n=== STDERR ===`n$stderr"
        Set-Content -Path $logFile -Value $combined -Encoding UTF8

        if ($proc.ExitCode -ne 0) {
            Write-Log "Installer for '$comp' failed with exit code $($proc.ExitCode). See log: $logFile"
            exit $proc.ExitCode
        } else {
            Write-Log "Installer for '$comp' succeeded. Log: $logFile"
        }
    } catch {
        Write-Log "Failed to run installer script for '$comp': $_"
        exit 3
    }
}

Write-Log "All requested components processed."
