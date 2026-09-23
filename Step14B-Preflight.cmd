@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
set "CFG=%~dp0importer.step14b.pilot.json"
echo === Step 14B worker allowlist preflight ===
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll worker-preflight --config "%CFG%" --worker-root "%ROOT%"
if errorlevel 1 exit /b %errorlevel%
echo.
echo === Step 14B exact allowlist collision/ownership recheck ===
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll solr-collision-audit --config "%CFG%" --worker-root "%ROOT%" --candidate-ids 1180000,1180001,1180002,1180003,1180097 --max-id-lookups 1000 --report-dir ".\solr-collision-audit-reports"
if errorlevel 1 exit /b %errorlevel%
echo.
echo STEP 14B PREFLIGHT COMPLETE. No MariaDB rows or Solr documents were changed.
popd
exit /b 0
