@echo off
setlocal
pushd "%~dp0" || exit /b 1
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File ".\ops\Install-Step13Task.ps1" -StartNow %*
set rc=%errorlevel%
popd
exit /b %rc%
