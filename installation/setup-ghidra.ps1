param([switch]$AutoDetect)

Write-Host ""
Write-Host "=== Ghidra Setup ===" -ForegroundColor Cyan
Write-Host ""

# Search for Ghidra on Desktop
$desktop = "$env:USERPROFILE\Desktop"
$ghidraFolders = Get-ChildItem -Path $desktop -Filter "ghidra*" -Directory -ErrorAction SilentlyContinue

if ($ghidraFolders) {
    $baseFolder = $ghidraFolders[0].FullName
    Write-Host "Found Ghidra folder: $baseFolder" -ForegroundColor Cyan
    
    # Check if there's a nested Ghidra folder (common with official downloads)
    $nestedGhidra = Get-ChildItem -Path $baseFolder -Filter "ghidra*" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($nestedGhidra) {
        $ghidraPath = $nestedGhidra.FullName
        Write-Host "Using nested folder: $ghidraPath" -ForegroundColor Cyan
    } else {
        $ghidraPath = $baseFolder
    }
    
    # Check for analyzeHeadless
    $analyzeHeadless = Join-Path $ghidraPath "support\analyzeHeadless.bat"
    if (Test-Path $analyzeHeadless) {
        Write-Host "Verified: analyzeHeadless.bat exists" -ForegroundColor Green
        
        # Configure it - use Python helper to avoid encoding issues
        $pythonConfigCode = "import sys; sys.path.insert(0, r'C:\!Everything Programming\Github Projects\FYP\Identifying-Cryptographic-Function-in-Blockchain\src'); from auditor.detectors.static_detection import config; config.set_ghidra_install_dir(r'$ghidraPath'); print('Config saved')"
        
        try {
            $output = python -c $pythonConfigCode 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Verified: Configuration saved via Python" -ForegroundColor Green
                
                # Double-check it works
                $verifyCode = "import sys; sys.path.insert(0, r'C:\!Everything Programming\Github Projects\FYP\Identifying-Cryptographic-Function-in-Blockchain\src'); from auditor.detectors.static_detection import ghidra_adapter; result = ghidra_adapter.resolve_ghidra({}); print(result if result else 'NOT_FOUND')"
                $verified = python -c $verifyCode 2>&1
                
                if ($verified -and $verified -ne 'NOT_FOUND') {
                    Write-Host ""
                    Write-Host "SUCCESS: Ghidra configured and verified!" -ForegroundColor Green
                    Write-Host "  Path: $ghidraPath" -ForegroundColor Cyan
                    Write-Host "  Resolved: $verified" -ForegroundColor Cyan
                    Write-Host ""
                    exit 0
                } else {
                    Write-Host ""
                    Write-Host "WARNING: Config saved but verification failed" -ForegroundColor Yellow
                    Write-Host "  Try restarting your terminal" -ForegroundColor Yellow
                    Write-Host ""
                    exit 0
                }
            }
        } catch {
            Write-Host "ERROR: Failed to configure via Python: $_" -ForegroundColor Red
            exit 1
        }
        
        Write-Host "ERROR: Unexpected failure" -ForegroundColor Red
        exit 1
    } else {
        Write-Host "ERROR: analyzeHeadless.bat not found in $ghidraPath\support" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "No Ghidra folder found on Desktop" -ForegroundColor Yellow
    Write-Host "Expected to find: $desktop\ghidra*" -ForegroundColor Yellow
    exit 1
}
