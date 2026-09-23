@echo off
setlocal
if "%~1"=="" (
  echo Usage: %~nx0 ^<mutation-id^>
  echo Example: %~nx0 5
  exit /b 2
)
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll solr-execute --mutation-id "%~1" --worker-root "%ROOT%"
exit /b %ERRORLEVEL%
