@echo off
setlocal
cd /d "%~dp0"
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll solr-build-payloads --worker-root "\\FLOSVR01\FastTrack\Candidate\To 1189999" --report-dir ".\solr-payload-reports"
endlocal
