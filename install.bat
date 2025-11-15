@echo off
REM CryptoScope - Installation Script
REM Installs Python dependencies and Ghidra

setlocal
cd /d "%~dp0"

set "skipghidra=0"
set "force=0"

REM Parse arguments
:parse_args
if "%1"=="" goto args_done
if /i "%1"=="-SkipGhidra" set "skipghidra=1"
if /i "%1"=="--SkipGhidra" set "skipghidra=1"
if /i "%1"=="-Force" set "force=1"
if /i "%1"=="--Force" set "force=1"
shift
goto parse_args

:args_done
echo.
echo CryptoScope - Installation Script
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorlevel% equ 0 (
    echo WARNING: Running as Administrator is not recommended
    echo This may cause permission issues later
    echo.
)

REM Step 1: Check Python
echo Step 1: Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found on PATH
    echo Please install Python 3.10-3.13 from https://www.python.org
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set "pyver=%%v"
echo Found Python: %pyver%
echo.

REM Step 2: Create virtual environment
echo Step 2: Setting up virtual environment...
if exist ".venv" (
    if %force% equ 1 (
        echo Removing existing venv...
        rmdir /s /q ".venv" >nul 2>&1
        if exist ".venv" (
            echo ERROR: Could not delete venv. Try closing terminals.
            pause
            exit /b 1
        )
    ) else (
        echo Virtual environment already exists
    )
)

if not exist ".venv" (
    echo Creating virtual environment...
    python -m venv ".venv"
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
)
echo.

REM Step 3: Install dependencies
echo Step 3: Installing Python packages...
.venv\Scripts\pip.exe install -q --no-cache-dir -r requirements.txt >nul 2>&1
if errorlevel 1 (
    echo Retrying...
    .venv\Scripts\pip.exe install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install packages
        pause
        exit /b 1
    )
)
echo Python packages installed
echo.

REM Step 4: Ghidra (optional)
if %skipghidra% equ 1 (
    echo Skipping Ghidra setup
) else (
    echo Step 4: Setting up Ghidra...
    REM Ghidra setup could go here
    echo Ghidra setup skipped for now
)
echo.

REM Step 5: Validate
echo Step 5: Validating installation...
.venv\Scripts\python.exe -c "import customtkinter; import supabase" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to import required modules
    pause
    exit /b 1
)
echo All dependencies validated
echo.
echo Installation Complete!
echo.
echo Next step: run.bat
echo.

endlocal
exit /b 0
