@echo off
rem Build AirMon installer (single self-contained exe, no external tools)
rem Usage: build_installer.bat
rem   Prereq: ..\build\airmon.exe must exist (run ..\build.bat first)
setlocal
cd /d "%~dp0"

set "GCC=f:\Users\26516\Desktop\sgl-vscode-v1.0\mingw64\bin\gcc.exe"
set "WINDRES=f:\Users\26516\Desktop\sgl-vscode-v1.0\mingw64\bin\windres.exe"
if not exist "%GCC%" set "GCC=gcc"
if not exist "%WINDRES%" set "WINDRES=windres"

if not exist "..\build\airmon.exe" (
    echo ERROR: ..\build\airmon.exe not found. Build the app first: ..\build.bat
    exit /b 1
)
if not exist "..\viewer.html" (
    echo ERROR: ..\viewer.html not found.
    exit /b 1
)

echo [1/3] compiling resources (embedding airmon.exe + viewer.html)...
"%WINDRES%" -I. installer.rc -O coff -o installer_res.o
if errorlevel 1 goto :err

echo [2/3] compiling installer...
"%GCC%" -std=c11 -O2 -Wall -c installer.c -o installer.o
if errorlevel 1 goto :err

echo [3/3] linking...
rem no -municode: entry is plain WinMain, wide cmdline comes from GetCommandLineW
"%GCC%" installer.o installer_res.o -o "..\build\AirMon-Setup.exe" -mwindows -lole32 -loleaut32 -lshell32 -lcomctl32 -lshlwapi -luuid -ladvapi32 -luser32 -lgdi32
if errorlevel 1 goto :err

echo.
echo Build OK: build\AirMon-Setup.exe
for %%F in ("..\build\AirMon-Setup.exe") do echo Size: %%~zF bytes
exit /b 0

:err
echo BUILD FAILED
exit /b 1
