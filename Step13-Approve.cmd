@echo off
setlocal
if "%~1"=="" (
  echo Usage: Step13-Approve.cmd ^<mutation-id^>
  exit /b 2
)
pushd "%~dp0" || exit /b 1
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File ".\ops\Approve-Step13Mutation.ps1" -MutationId %~1
set rc=%errorlevel%
popd
exit /b %rc%
