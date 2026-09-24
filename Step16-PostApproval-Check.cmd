@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
echo === Step 16 baseline status ===
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-status --config ".\importer.step15.pilot.json"
if errorlevel 1 goto :fail

echo.
echo === Step 16 triage after approval ===
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-triage --config ".\importer.step15.pilot.json" --worker-root "%ROOT%" --report-dir ".\baseline-triage-reports"
if errorlevel 1 goto :fail

echo.
echo === Step 16 recovery safety inspection ===
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll recovery-inspect --config ".\importer.step15.pilot.json" --worker-root "%ROOT%" --report-dir ".\recovery-reports"
if errorlevel 1 goto :fail

echo.
echo STEP 16 POST-APPROVAL CHECK COMPLETE. No automatic Solr apply was performed.
popd
exit /b 0
:fail
set rc=%errorlevel%
echo.
echo STEP 16 POST-APPROVAL CHECK FAILED. Review the command above. No automatic Solr apply was requested by this script.
popd
exit /b %rc%
