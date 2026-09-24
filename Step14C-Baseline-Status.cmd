@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "CFG=%~dp0importer.step14b.pilot.json"
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-status --config "%CFG%" %*
set rc=%errorlevel%
popd
exit /b %rc%
