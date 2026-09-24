@echo off
setlocal
if "%~1"=="" (
  echo Usage: Step14C-Baseline-Approve.cmd ^<candidate-id^> ^<baseline-sha256^> [--apply]
  exit /b 2
)
if "%~2"=="" (
  echo Usage: Step14C-Baseline-Approve.cmd ^<candidate-id^> ^<baseline-sha256^> [--apply]
  exit /b 2
)
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
set "CFG=%~dp0importer.step14b.pilot.json"
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-approve --config "%CFG%" --candidate-id "%~1" --baseline-sha256 "%~2" --worker-root "%ROOT%" %3 %4 %5 %6 %7 %8 %9
set rc=%errorlevel%
popd
exit /b %rc%
