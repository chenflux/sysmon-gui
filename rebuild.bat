@echo off
setlocal
cd /d "%~dp0"

echo [1/3] Stopping running sysmon-gui instance ...
taskkill /IM sysmon-gui.exe /F >nul 2>&1
timeout /t 1 /nobreak >nul

echo [2/3] Cleaning previous build ...
call clean.bat
if errorlevel 1 (
    echo Rebuild ABORTED: clean failed.
    exit /b 1
)

echo [3/3] Building ...
call build.bat
if errorlevel 1 (
    echo Rebuild FAILED.
    exit /b 1
)

endlocal
