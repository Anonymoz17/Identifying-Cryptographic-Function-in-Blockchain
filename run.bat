@echo off
REM CryptoScope Application Launcher
REM This batch file activates the virtual environment and runs the app

setlocal enabledelayedexpansion

REM Get project root (directory containing this batch file)
set SCRIPT_DIR=%~dp0
set REPO_ROOT=%SCRIPT_DIR%

REM Paths
set VENV_PATH=%REPO_ROOT%.venv
set PYTHON_EXE=%VENV_PATH%\Scripts\python.exe
set APP_PY=%REPO_ROOT%src\app.py

REM Check if venv exists
if not exist "%PYTHON_EXE%" (
    echo [ERROR] Virtual environment not found at %VENV_PATH%
    echo.
    echo Please run the installer first:
    echo   .\install.ps1
    echo.
    echo Or from Command Prompt:
    echo   powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
    echo.
    pause
    exit /b 1
)

REM Check if app.py exists
if not exist "%APP_PY%" (
    echo [ERROR] app.py not found at %APP_PY%
    echo.
    pause
    exit /b 1
)

REM Launch the app
echo [INFO] Launching CryptoScope...
echo.

"%PYTHON_EXE%" "%APP_PY%"

exit /b %ERRORLEVEL%
