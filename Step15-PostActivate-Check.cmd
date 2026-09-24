@echo off
setlocal
pushd "%~dp0" || exit /b 1
echo === Step 15 baseline enrollment status ===
call .\Step15-Baseline-Status.cmd
if errorlevel 1 exit /b %errorlevel%
echo.
echo === Step 15 recovery/safety inspection ===
call .\Step14D-Recovery-Inspect.cmd
if errorlevel 1 exit /b %errorlevel%
echo.
echo === Step 15 pilot metrics ===
call .\Step15-Report.cmd
if errorlevel 1 exit /b %errorlevel%
echo.
echo STEP 15 POST-ACTIVATION CHECK COMPLETE. No automatic Solr apply was performed.
popd
exit /b 0
