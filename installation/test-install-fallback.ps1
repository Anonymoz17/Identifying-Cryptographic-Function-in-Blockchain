<#
Quick smoke test for installer PowerShell fallback (installed under installation/).
This script:
 - Creates a minimal zip package containing a top-level folder with support/analyzeHeadless.bat
 - Temporarily disables installation/set_ghidra_config.py to force the PowerShell fallback
 - Runs installation/install-ghidra.ps1 with -ForceFallback and checks %APPDATA%/cryptoscope/config.json
 - Calls uninstall to clean up the installed test folder and persisted config
 - Restores the helper and removes temp files

Usage (from repo root):
  pwsh -File .\installation\test-install-fallback.ps1

This test is non-destructive to your main Ghidra install because it uses a unique version string.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Get-Location).Path
& "$PSScriptRoot\..\tests\test-install-fallback.ps1" @Args
$helperDisabled = $helper + '.disabled'
