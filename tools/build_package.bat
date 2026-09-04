@echo off
:: ============================================================================
:: One-click build + package (Release x64)
::   1) locate VS (vswhere) and Qt (QTDIR)
::   2) qmake + nmake compile the app       -> release\SCUTNetLogin.exe
::   3) compile + run unit tests            -> all green, or stop
::   4) build the installer                 -> release\SCUTNetLogin-Setup.exe
:: Run from repo root:  tools\build_package.bat
:: Prereqs: VS2022 (Desktop C++), Qt 6.11.0 msvc2022_64, Npcap SDK (C:\npcap-sdk)
:: NOTE: keep this file pure ASCII (cmd reads .bat as Windows ANSI).
:: ============================================================================
setlocal enabledelayedexpansion

set "ROOT=%~dp0.."
cd /d "%ROOT%"

rem ---- locate Visual Studio ----
set "VSDIR="
for /f "usebackq delims=" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do set "VSDIR=%%i"
if "%VSDIR%"=="" (
    echo [ERR] Visual Studio 2022 not found. Install it or set VSDIR manually.
    exit /b 1
)
echo [1/4] VS: %VSDIR%

set "QTDIR=C:\Qt\6.11.0\msvc2022_64"
if not exist "%QTDIR%\bin\qmake.exe" (
    echo [ERR] Qt not found at %QTDIR%\bin\qmake.exe - edit QTDIR at the top of this file.
    exit /b 1
)
echo [1/4] Qt: %QTDIR%

call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 ( echo [ERR] vcvars64 failed & exit /b 1 )

echo [2/4] Building app (release, x64)...
"%QTDIR%\bin\qmake.exe" "%ROOT%\SCUTNetLogin.pro" || ( echo [ERR] qmake app failed & exit /b 1 )
nmake release || ( echo [ERR] building app failed & exit /b 1 )

echo [3/4] Building and running unit tests...
cd /d "%ROOT%\tests"
"%QTDIR%\bin\qmake.exe" "%ROOT%\tests\tst_packets.pro" || ( echo [ERR] qmake tests failed & exit /b 1 )
nmake release || ( echo [ERR] building tests failed & exit /b 1 )
set "PATH=%QTDIR%\bin;%PATH%"
"%ROOT%\tests\release\tst_packets.exe" || ( echo [ERR] unit tests failed & cd /d "%ROOT%" & exit /b 1 )
cd /d "%ROOT%"

echo [4/4] Building installer...
powershell -ExecutionPolicy Bypass -File "%ROOT%\tools\installer\build_installer.ps1" || ( echo [ERR] building installer failed & exit /b 1 )

echo.
echo ============================================================
echo   DONE  app:   release\SCUTNetLogin.exe
echo        setup:  release\SCUTNetLogin-Setup.exe
echo ============================================================
exit /b 0
