param(
    [string]$Version = "10.2.3",
    [string]$Dest = "$env:USERPROFILE\ghidra",
    [switch]$AcceptLicense
)

if (-not $AcceptLicense) {
    Write-Host "You must accept the Ghidra license to download. Re-run with -AcceptLicense to confirm you accept the license terms."
    exit 1
}

# NOTE: Update the download URL and SHA256 checksum below when bumping versions.
$zipUrl = "https://ghidra-sre.org/ghidra_${Version}_PUBLIC.zip"
$expectedSha256 = "<REPLACE_WITH_REAL_SHA256>"  # replace with the official checksum

$tmp = Join-Path $env:TEMP ("ghidra_$Version.zip")
Write-Host "Downloading Ghidra $Version to $tmp"
Invoke-WebRequest -Uri $zipUrl -OutFile $tmp -UseBasicParsing

Write-Host "Verifying checksum (SHA256)..."
try {
    $hash = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
    if ($expectedSha256 -ne "<REPLACE_WITH_REAL_SHA256>" -and $hash -ne $expectedSha256.ToLower()) {
        Write-Host "Checksum mismatch: expected $expectedSha256 got $hash"
        exit 2
    }
} catch {
    Write-Host "Checksum verification failed: $_"
    exit 2
}

Write-Host "Extracting to $Dest"
if (Test-Path $Dest) {
    Write-Host "Destination exists; attempting to remove and re-create"
    try { Remove-Item -Recurse -Force $Dest } catch { }
}
New-Item -ItemType Directory -Path $Dest -Force | Out-Null

Expand-Archive -Path $tmp -DestinationPath $Dest -Force

Write-Host "Ghidra should now be available under $Dest."
Write-Host "Set the environment variable GHIDRA_INSTALL_DIR to the directory that contains 'support/analyzeHeadless' or add that directory to PATH."
