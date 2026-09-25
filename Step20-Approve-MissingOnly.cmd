@echo off
setlocal
if "%~1"=="" (
  echo Usage: Step20-Approve-MissingOnly.cmd ^<candidate-id^> ^<baseline-sha256^> [--ack-missing-only --apply]
  exit /b 2
)
if "%~2"=="" (
  echo Usage: Step20-Approve-MissingOnly.cmd ^<candidate-id^> ^<baseline-sha256^> [--ack-missing-only --apply]
  exit /b 2
)
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-approve-step20-missing-only --config ".\importer.step15.pilot.json" --candidate-id "%~1" --baseline-sha256 "%~2" --worker-root "%ROOT%" %3 %4 %5 %6 %7 %8 %9
set rc=%errorlevel%
popd
exit /b %rc%
