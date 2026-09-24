@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-capture --config ".\importer.step15.pilot.json" --worker-root "%ROOT%" --report-dir ".\baseline-reports"
popd
exit /b %errorlevel%
