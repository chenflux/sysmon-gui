@echo off
setlocal
cd /d "%~dp0"

echo [1/2] Stopping running sysmon-gui instance ...
taskkill /IM sysmon-gui.exe /F >nul 2>&1
timeout /t 1 /nobreak >nul

echo [2/2] Removing dist directory ...
if not exist dist (
    echo Nothing to clean - dist does not exist.
    goto :done
)

if /i "%~1"=="-full" (
    echo   (full clean: no user data backup^)
) else (
    if exist dist\rules.json (
        copy /y dist\rules.json rules.backup.json >nul
        echo   User rules backed up to: rules.backup.json
    )
)

rmdir /s /q dist
if exist dist (
    echo.
    echo WARNING: dist could not be fully removed.
    echo   - close the Sysmon GUI window first, or
    echo   - if it was started as Administrator, run this script as Administrator too.
    exit /b 1
)

echo Clean OK.
:done
endlocal
