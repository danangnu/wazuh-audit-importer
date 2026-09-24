@echo off
setlocal
pushd "%~dp0" || exit /b 1
echo === Step 14E safety/recovery preflight ===
call .\Step14D-Preflight.cmd
if errorlevel 1 exit /b %errorlevel%
echo.
echo === Step 14E pilot metrics / delivery report ===
call .\Step14E-Report.cmd
if errorlevel 1 exit /b %errorlevel%
echo.
echo STEP 14E PREFLIGHT PASS. Metrics/report generated. No Solr writes occurred.
popd
exit /b 0
