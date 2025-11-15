@echo off
REM CryptoScope - First-Time Setup
REM Simple, reliable setup that installs and launches the app

setlocal
cd /d "%~dp0"

echo.
echo CryptoScope - First-Time Setup
echo.

REM Check if required files exist
if not exist "install.bat" (
    echo ERROR: install.bat not found
    pause
    exit /b 1
)
if not exist "run.bat" (
    echo ERROR: run.bat not found
    pause
    exit /b 1
)
if not exist "requirements.txt" (
    echo ERROR: requirements.txt not found
    pause
    exit /b 1
)
if not exist "src\app.py" (
    echo ERROR: src\app.py not found
    pause
    exit /b 1
)

echo All files validated
echo.
echo Running installation...
echo.

call install.bat
if errorlevel 1 (
    echo Installation failed
    pause
    exit /b 1
)

echo.
echo Launching CryptoScope...
echo.

call run.bat
set exitcode=%errorlevel%

echo.
echo CryptoScope closed
echo.
echo To run again, use: run.bat
echo.

endlocal
exit /b %exitcode%
