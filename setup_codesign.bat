@echo off
rem 一次性安装本机代码签名证书, 并给现有 exe 签名
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_codesign.ps1"
echo.
pause
