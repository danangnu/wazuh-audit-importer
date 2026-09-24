@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
set "CFG=%~dp0importer.step14b.pilot.json"
set "REPORT=%~dp0recovery-reports"
if "%~1"=="" (
  dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll recovery-inspect --config "%CFG%" --worker-root "%ROOT%" --report-dir "%REPORT%"
) else (
  dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll recovery-inspect --config "%CFG%" --worker-root "%ROOT%" --candidate-id "%~1" --report-dir "%REPORT%"
)
set rc=%errorlevel%
popd
exit /b %rc%
