@echo off
setlocal
pushd "%~dp0" || exit /b 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\ops\Activate-Step15.ps1" %*
popd
exit /b %errorlevel%
