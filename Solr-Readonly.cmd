@echo off
setlocal
set "ROOT=%~1"
if "%ROOT%"=="" set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
dotnet ".\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll" solr-readonly --worker-root "%ROOT%" --report-dir ".\solr-readonly-reports"
exit /b %ERRORLEVEL%
