@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
set "CFG=%~dp0importer.step15.pilot.json"
set "IDS=1180000,1180001,1180002,1180003,1180004,1180005,1180006,1180007,1180008,1180009,1180010,1180011,1180012,1180013,1180014,1180015,1180016,1180017,1180018,1180019,1180020,1180021,1180022,1180023,1180097"
echo === Step 15 25-candidate worker allowlist preflight ===
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll worker-preflight --config "%CFG%" --worker-root "%ROOT%"
if errorlevel 1 exit /b %errorlevel%
echo.
echo === Step 15 exact 25-candidate collision/ownership recheck ===
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll solr-collision-audit --config "%CFG%" --worker-root "%ROOT%" --candidate-ids %IDS% --max-id-lookups 1000 --report-dir ".\solr-collision-audit-reports"
if errorlevel 1 exit /b %errorlevel%
echo.
echo STEP 15 PREFLIGHT COMPLETE. Candidate metadata and Solr ownership were read only; no MariaDB rows or Solr documents were changed.
popd
exit /b 0
