@echo off
setlocal
pushd "%~dp0" || exit /b 1
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
set "CFG=%~dp0importer.step14b.pilot.json"
echo === Step 14C allowlist/collision preflight ===
call .\Step14B-Preflight.cmd
if errorlevel 1 exit /b %errorlevel%
echo.
echo === Step 14C baseline enrollment status ===
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll baseline-status --config "%CFG%"
if errorlevel 1 exit /b %errorlevel%
echo.
echo STEP 14C PREFLIGHT COMPLETE. Baseline-pending candidates remain blocked from Step 10A/10B/11.
popd
exit /b 0
