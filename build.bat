@echo off
rem airmon build script - MinGW-w64 gcc (pure ASCII only, cmd needs ANSI)
rem Usage: build.bat [clean]
setlocal
cd /d "%~dp0"

set "GCC=f:\Users\26516\Desktop\sgl-vscode-v1.0\mingw64\bin\gcc.exe"
if not exist "%GCC%" set "GCC=gcc"

if "%~1"=="clean" (
    if exist build rmdir /s /q build
    exit /b
)

if not exist build mkdir build

rem ble.c is pure C (WinRT ABI via COM vtables)
"%GCC%" -std=c11 -O2 -Wall -c src\ble.c -o build\ble.o
if errorlevel 1 goto :err

"%GCC%" -std=c11 -O2 -Wall -c src\main.c -o build\main.o
if errorlevel 1 goto :err
"%GCC%" -std=c11 -O2 -Wall -c src\ui.c -o build\ui.o
if errorlevel 1 goto :err
"%GCC%" -std=c11 -O2 -Wall -c src\gatt.c -o build\gatt.o
if errorlevel 1 goto :err
"%GCC%" -std=c11 -O2 -Wall -c src\notify.c -o build\notify.o
if errorlevel 1 goto :err
"%GCC%" -std=c11 -O2 -Wall -c src\trayicon.c -o build\trayicon.o
if errorlevel 1 goto :err
"%GCC%" -std=c11 -O2 -Wall -c src\airlog.c -o build\airlog.o
if errorlevel 1 goto :err
"%GCC%" -std=c11 -O2 -Wall -c src\timesync.c -o build\timesync.o
if errorlevel 1 goto :err

set "SQLDEF="
set "SQLITE_OBJ="
if exist third_party\sqlite3.c (
    set "SQLDEF=-DHAVE_SQLITE"
    "%GCC%" -std=c11 -O2 -c third_party\sqlite3.c -o build\sqlite3.o
    if errorlevel 1 goto :err
    set "SQLITE_OBJ=build\sqlite3.o"
)

"%GCC%" -std=c11 -O2 -Wall %SQLDEF% -c src\store.c -o build\store.o
if errorlevel 1 goto :err

"%GCC%" build\main.o build\ble.o build\gatt.o build\notify.o build\trayicon.o build\airlog.o build\timesync.o build\store.o build\ui.o %SQLITE_OBJ% -o build\airmon.exe -municode -mwindows -lole32 -loleaut32 -lruntimeobject -lws2_32 -lshell32 -lgdi32 -luser32 -ladvapi32 -lbthprops -lm
if errorlevel 1 goto :err

echo Build OK: build\airmon.exe
exit /b 0

:err
echo BUILD FAILED
exit /b 1
