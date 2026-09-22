@echo off
setlocal
pushd "%~dp0" || exit /b 1
if "%~1"=="" goto usage
if "%~2"=="" goto usage
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll work --worker-root "%~1" --state-dir "%~2"
set rc=%errorlevel%
popd
exit /b %rc%
:usage
echo Usage: Work.cmd "\\FLOSVR01\share\...\To 1189999" "C:\path\to\persistent\worker-state"
popd
exit /b 2
