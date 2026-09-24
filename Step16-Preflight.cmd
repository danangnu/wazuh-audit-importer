@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
echo === Step 16 operational preflight ===
call .\Step13-Preflight.cmd
if errorlevel 1 goto :fail

echo.
echo === Step 16 read-only baseline triage ===
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-triage --config ".\importer.step15.pilot.json" --worker-root "%ROOT%" --report-dir ".\baseline-triage-reports"
if errorlevel 1 goto :fail

echo.
echo STEP 16 PREFLIGHT PASS. Triage generated; no baseline approval or Solr write occurred.
popd
exit /b 0
:fail
set rc=%errorlevel%
echo.
echo STEP 16 PREFLIGHT FAILED. Do not approve a baseline until the failure is understood.
popd
exit /b %rc%
