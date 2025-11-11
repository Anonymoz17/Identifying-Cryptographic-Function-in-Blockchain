# Compile-TestBinaries.ps1
# Compiles test C files to create executable binaries for dynamic analysis testing

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Test Case Binary Compilation" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check if cl.exe (Visual Studio) is available
$cl_path = Get-Command cl.exe -ErrorAction SilentlyContinue

if ($null -eq $cl_path) {
    Write-Host "❌ Visual Studio Build Tools not found (cl.exe not in PATH)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "1. Install Visual Studio Build Tools with C/C++ support"
    Write-Host "2. Use 'Developer Command Prompt for Visual Studio'"
    Write-Host "3. Use MinGW: gcc crypto_utils.c -o crypto_utils.exe -lbcrypt"
    Write-Host "4. Copy system binaries: Copy-Item C:\Windows\System32\certutil.exe ."
    Write-Host ""
    exit 1
}

Write-Host "✓ Found cl.exe at: $($cl_path.Source)" -ForegroundColor Green
Write-Host ""

$script_dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Working directory: $script_dir" -ForegroundColor Gray
Write-Host ""

# Compile crypto_utils.c
Write-Host "[1/2] Compiling crypto_utils.c..." -ForegroundColor Yellow
$crypto_c = Join-Path $script_dir "crypto_utils.c"
$crypto_exe = Join-Path $script_dir "crypto_utils.exe"

if (Test-Path $crypto_c) {
    try {
        cl.exe "$crypto_c" /Fe"$crypto_exe" /link bcrypt.lib ncrypt.lib kernel32.lib 2>&1 | Out-Null
        if (Test-Path $crypto_exe) {
            $size = (Get-Item $crypto_exe).Length / 1KB
            Write-Host "✓ Created: crypto_utils.exe ($([math]::Round($size))KB)" -ForegroundColor Green
        }
    } catch {
        Write-Host "✗ Failed to compile crypto_utils.c: $_" -ForegroundColor Red
    }
} else {
    Write-Host "✗ File not found: crypto_utils.c" -ForegroundColor Red
}

Write-Host ""

# Compile file_utils.c
Write-Host "[2/2] Compiling file_utils.c..." -ForegroundColor Yellow
$file_c = Join-Path $script_dir "file_utils.c"
$file_exe = Join-Path $script_dir "file_utils.exe"

if (Test-Path $file_c) {
    try {
        cl.exe "$file_c" /Fe"$file_exe" /link kernel32.lib 2>&1 | Out-Null
        if (Test-Path $file_exe) {
            $size = (Get-Item $file_exe).Length / 1KB
            Write-Host "✓ Created: file_utils.exe ($([math]::Round($size))KB)" -ForegroundColor Green
        }
    } catch {
        Write-Host "✗ Failed to compile file_utils.c: $_" -ForegroundColor Red
    }
} else {
    Write-Host "✗ File not found: file_utils.c" -ForegroundColor Red
}

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Files in test_case directory:" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

$files = Get-ChildItem $script_dir | Where-Object { $_.PSIsContainer -eq $false }
foreach ($file in $files) {
    $type = $file.Extension
    if ($type -eq ".exe") {
        $size = "{0:N0}" -f ($file.Length)
        Write-Host "  ✓ $($file.Name) (Binary, $size bytes)" -ForegroundColor Green
    } elseif ($type -eq ".py") {
        $size = "{0:N0}" -f ($file.Length)
        Write-Host "  ○ $($file.Name) (Python source, $size bytes)" -ForegroundColor Cyan
    } elseif ($type -eq ".c") {
        $size = "{0:N0}" -f ($file.Length)
        Write-Host "  ○ $($file.Name) (C source, $size bytes)" -ForegroundColor Cyan
    } else {
        Write-Host "  ○ $($file.Name)" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Load this test_case as a Case in Detectors page"
Write-Host "2. Run Setup (processes source files)"
Write-Host "3. Run Static Analysis (analyzes patterns)"
Write-Host "4. Run Dynamic Analysis (shows crypto call traces)"
Write-Host ""
