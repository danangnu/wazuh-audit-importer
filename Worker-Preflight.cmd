@echo off
setlocal
pushd "%~dp0" || exit /b 1
if "%~1"=="" (
  echo Usage: Worker-Preflight.cmd "\\FLOSVR01\share\...\To 1189999"
  popd
  exit /b 2
)
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll worker-preflight --worker-root "%~1"
set rc=%errorlevel%
popd
exit /b %rc%
