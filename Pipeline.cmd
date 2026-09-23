@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
set "STATE=%~dp0worker-state"
set "REPORT=%~dp0pipeline-reports"
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll pipeline --worker-root "%ROOT%" --state-dir "%STATE%" --report-dir "%REPORT%" %*
set rc=%errorlevel%
popd
exit /b %rc%
