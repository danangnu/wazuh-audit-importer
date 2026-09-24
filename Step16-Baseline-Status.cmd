@echo off
setlocal
pushd "%~dp0" || exit /b 1
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-status --config ".\importer.step15.pilot.json" %*
set rc=%errorlevel%
popd
exit /b %rc%
