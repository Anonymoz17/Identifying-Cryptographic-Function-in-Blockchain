@echo off
REM CryptoScope Setup Batch File
REM This file allows users to run setup without dealing with PowerShell execution policies

setlocal enabledelayedexpansion

echo.
echo CryptoScope - Setup Helper
echo.

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"

REM Remove trailing backslash if present
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

REM Run PowerShell with ExecutionPolicy Bypass to run setup.ps1
powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%SCRIPT_DIR%\setup.ps1'"

REM Capture the exit code
set "EXIT_CODE=!ERRORLEVEL!"

REM Exit with the same code as PowerShell
exit /b !EXIT_CODE!
