@echo off
setlocal
cd /d "%~dp0"
set "LIMIT=%~1"
if "%LIMIT%"=="" set "LIMIT=10"

dotnet ".\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll" solr-collision-audit ^
  --worker-root "\\FLOSVR01\FastTrack\Candidate\To 1189999" ^
  --candidate-limit "%LIMIT%" ^
  --max-id-lookups 1000 ^
  --report-dir ".\solr-collision-audit-reports"

exit /b %ERRORLEVEL%
