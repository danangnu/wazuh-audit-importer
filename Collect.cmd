@echo off
setlocal
set "ROOT=%~dp0"
dotnet "%ROOT%src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll" collect %*
exit /b %ERRORLEVEL%
