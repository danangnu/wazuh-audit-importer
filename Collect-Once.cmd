@echo off
setlocal
pushd "%~dp0" || exit /b 1
if not exist "src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll" (
  echo ERROR: Build the solution first. No collection attempted.
  popd
  exit /b 1
)
echo This requires an existing SSH tunnel from 127.0.0.1:19200 to Wazuh Indexer 127.0.0.1:9200.
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll collect-once
set rc=%ERRORLEVEL%
popd
exit /b %rc%
