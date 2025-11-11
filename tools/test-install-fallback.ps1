param(
    [Parameter(ValueFromRemainingArguments=$true)]
    $RemainingArgs
)

Write-Host "tools/test-install-fallback.ps1 is deprecated; using installation/test-install-fallback.ps1 instead"

$script = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) "..\installation\test-install-fallback.ps1"
$script = (Resolve-Path $script).ProviderPath

& "$script" $RemainingArgs
