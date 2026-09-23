@echo off
setlocal
if "%~1"=="" (
  echo Usage: %~nx0 ^<mutation-id^>
  echo This command performs actual Solr writes after Step 11 safety gates pass.
  echo Example: %~nx0 5
  exit /b 2
)
set "ROOT=\\FLOSVR01\FastTrack\Candidate\To 1189999"
echo WARNING: --apply can DELETE/ADD documents in the approved AlliedSolrCore.
echo Mutation requested: %~1
set /p CONFIRM=Type APPLY-%~1 to continue: 
if /I not "%CONFIRM%"=="APPLY-%~1" (
  echo Cancelled. No command executed.
  exit /b 2
)
dotnet .\src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll solr-execute --mutation-id "%~1" --worker-root "%ROOT%" --apply
exit /b %ERRORLEVEL%
