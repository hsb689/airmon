@echo off
rem Export airmon.db to airmon.json and open viewer.html in the default browser
setlocal
cd /d "%~dp0"

if not exist tools\dbjson.exe (
    echo tools\dbjson.exe not found. Build it first:
    echo   gcc -std=c11 -O2 -w tools\dbjson.c third_party\sqlite3.c -o tools\dbjson.exe
    pause
    exit /b 1
)

echo Exporting database...
tools\dbjson.exe build\airmon.db build\airmon.json
if errorlevel 1 (
    echo Export failed.
    pause
    exit /b 1
)

echo Opening viewer...
start "" "%~dp0viewer.html"
