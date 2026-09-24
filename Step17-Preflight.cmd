@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
echo === Step 17 operational preflight ===
call .\Step13-Preflight.cmd
if errorlevel 1 goto :fail

echo.
echo === Step 17 initial SmallDrift review ===
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-review-small-drift --config ".\importer.step15.pilot.json" --worker-root "%ROOT%" --report-dir ".\baseline-small-drift-reports"
if errorlevel 1 goto :fail

echo.
echo STEP 17 PREFLIGHT PASS. Initial three-candidate drift evidence revalidated; no baseline approval or Solr write occurred.
popd
exit /b 0
:fail
set rc=%errorlevel%
echo.
echo STEP 17 PREFLIGHT FAILED. Do not approve SmallDrift enrollment until the failure is understood.
popd
exit /b %rc%
