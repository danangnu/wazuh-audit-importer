@echo off
setlocal
pushd "%~dp0" || exit /b 1
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File ".\ops\Activate-Step14B.ps1" %*
set rc=%errorlevel%
popd
exit /b %rc%
