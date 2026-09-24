@echo off
setlocal
pushd "%~dp0" || exit /b 1
echo === Step 14D baseline gate status ===
call .\Step14C-Baseline-Status.cmd
if errorlevel 1 exit /b %errorlevel%
echo.
echo === Step 14D recovery inspection ===
call .\Step14D-Recovery-Inspect.cmd
set rc=%errorlevel%
if %rc% GEQ 12 (
  echo.
  echo STEP 14D PREFLIGHT FOUND UNCERTAIN/INCONSISTENT MUTATION STATE. Review required; do not blind-retry.
  exit /b %rc%
)
if errorlevel 1 exit /b %errorlevel%
echo.
echo STEP 14D PREFLIGHT PASS. No uncertain processing/failed mutation was found. No Solr writes occurred.
popd
exit /b 0
