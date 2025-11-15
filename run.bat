@echo off
REM CryptoScope - Application Launcher

setlocal
cd /d "%~dp0"

REM Check if venv exists
if not exist ".venv\Scripts\python.exe" (
    echo ERROR: Virtual environment not found
    echo Please run: setup.bat
    pause
    exit /b 1
)

REM Check if app exists
if not exist "src\app.py" (
    echo ERROR: app.py not found
    pause
    exit /b 1
)

echo.
echo Launching CryptoScope...
echo.

.venv\Scripts\python.exe src\app.py
set exitcode=%errorlevel%

endlocal
exit /b %exitcode%
