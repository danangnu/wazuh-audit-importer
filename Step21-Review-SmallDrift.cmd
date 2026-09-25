@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
if "%~1"=="" (
  dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-review-step21-small-drift --config ".\importer.step15.pilot.json" --worker-root "%ROOT%" --report-dir ".\baseline-small-drift-reports"
) else (
  dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-review-step21-small-drift --config ".\importer.step15.pilot.json" --worker-root "%ROOT%" --report-dir ".\baseline-small-drift-reports" --candidate-id "%~1"
)
set rc=%errorlevel%
popd
exit /b %rc%
