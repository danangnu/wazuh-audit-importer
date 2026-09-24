@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
set "CANDOPT="
if not "%~1"=="" set "CANDOPT=--candidate-id %~1"
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-review-small-drift --config ".\importer.step15.pilot.json" --worker-root "%ROOT%" --report-dir ".\baseline-small-drift-reports" %CANDOPT%
set rc=%errorlevel%
popd
exit /b %rc%
