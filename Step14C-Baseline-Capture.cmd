@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
set "CFG=%~dp0importer.step14b.pilot.json"
set "REPORT=%~dp0baseline-reports"
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-capture --config "%CFG%" --worker-root "%ROOT%" --report-dir "%REPORT%" %*
set rc=%errorlevel%
popd
exit /b %rc%
