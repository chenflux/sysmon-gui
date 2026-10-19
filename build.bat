@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem --- Locate Go: prefer PATH, fallback to common locations ---
set GO=
where go >nul 2>nul && set GO=go
if not defined GO (
    if exist "E:\ai_apps\go1.24.0.windows-amd64\go\bin\go.exe" set "GO=E:\ai_apps\go1.24.0.windows-amd64\go\bin\go.exe"
)
if not defined GO (
    echo [ERROR] Go toolchain not found in PATH. Install Go 1.24+ or edit this script.
    exit /b 1
)

rem --- Version stamping (ldflags injection) ---
set VER=1.0.0
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd.HHmm"') do set BTIME=%%i
set REV=none
where git >nul 2>nul && for /f %%i in ('git rev-parse --short HEAD 2^>nul') do set REV=%%i

if not exist dist mkdir dist

echo [1/2] Building sysmon-gui.exe  (v%VER% build %BTIME% rev %REV%) ...
"%GO%" build -trimpath -ldflags "-s -w -H=windowsgui -X sysmon-gui/internal/version.Version=%VER% -X sysmon-gui/internal/version.BuildTime=%BTIME% -X sysmon-gui/internal/version.GitRev=%REV%" -o dist\sysmon-gui.exe .
if errorlevel 1 (
    echo Build FAILED.
    exit /b 1
)

echo [2/2] Done. Sysmon binaries are NOT bundled:
echo   - First run: the app offers to auto-download Sysmon from Microsoft Sysinternals
echo   - Or manually place Sysmon64.exe next to dist\sysmon-gui.exe (env SYSMON_EXE also works)

echo.
echo Build OK: dist\sysmon-gui.exe
echo Usage: double-click to run - standalone window (WebView2), auto UAC elevation
echo CLI: -ui window^|web^|none   -addr 127.0.0.1:8791   -data DIR   -no-elevate
endlocal
