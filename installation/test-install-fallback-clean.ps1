Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Get-Location).Path
$helper = Join-Path $repo 'installation\set_ghidra_config.py'
$helperDisabled = $helper + '.disabled'

Write-Host "Creating temp test archive"
$tmp = Join-Path $env:TEMP ("ghidra_test_zip_" + [Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp | Out-Null
$candidate = Join-Path $tmp 'ghidra_test_PUBLIC'
New-Item -ItemType Directory -Path (Join-Path $candidate 'support') -Force | Out-Null
Set-Content -Path (Join-Path $candidate 'support\analyzeHeadless.bat') -Value 'echo dummy analyzeHeadless' -Encoding ASCII
$zip = Join-Path $tmp 'ghidra_test_PUBLIC.zip'
Compress-Archive -Path $candidate -DestinationPath $zip -Force
Write-Host "Created zip: $zip"

if (-not (Test-Path $helper)) {
  Write-Warning "Helper not found at $helper; proceeding (fallback will be used)"
  $helperDisabled = $null
} else {
  Move-Item -Force -Path $helper -Destination $helperDisabled
  Write-Host "Disabled helper: $helperDisabled"
}

$sha = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLower()
Write-Host "SHA: $sha"

$testVersion = "test_fallback_" + ([Guid]::NewGuid().ToString())

$log = Join-Path $env:TEMP 'ghidra_install_test_fallback_log.txt'
& "$repo\installation\install-ghidra-clean.ps1" -ArchivePath $zip -Sha256 $sha -AcceptLicense -Version $testVersion -Force -ForceFallback *>&1 | Tee-Object -FilePath $log

Write-Host "--- installer log (tail) ---"
Get-Content -Path $log -Tail 200 | Write-Host

$cfgPath = Join-Path $env:APPDATA 'cryptoscope\config.json'
if (-not (Test-Path $cfgPath)) { Write-Error "Config file not found at $cfgPath" } else {
    $cfg = Get-Content -Raw -Path $cfgPath -Encoding UTF8 | ConvertFrom-Json
    if ($null -eq $cfg.ghidra -or $null -eq $cfg.ghidra.install_dir) { Write-Error "ghidra.install_dir missing in config" } else { Write-Host "Persisted install_dir: $($cfg.ghidra.install_dir)" }
}

Write-Host "Uninstalling test install"
& "$repo\installation\install-ghidra-clean.ps1" -Uninstall -Version $testVersion *>&1 | Tee-Object -FilePath $log
Get-Content -Path $log -Tail 200 | Write-Host

if ($helperDisabled -and (Test-Path $helperDisabled)) { Move-Item -Force -Path $helperDisabled -Destination $helper; Write-Host "Restored helper" } else { Write-Host "No helper to restore" }

Remove-Item -LiteralPath $tmp -Recurse -Force
Write-Host "Removed temp $tmp"

Write-Host "Test completed"
