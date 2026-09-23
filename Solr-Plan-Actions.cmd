@echo off
setlocal
cd /d "%~dp0"
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll solr-plan-actions --worker-root "%ROOT%" --report-dir ".\solr-action-reports"
endlocal
