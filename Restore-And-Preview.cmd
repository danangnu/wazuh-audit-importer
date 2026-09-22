@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Controlled NuGet retry for the existing WazuhAuditImporter solution.
rem Uses fresh per-run caches. Does not delete shared caches or source files.
rem Keeps NuGet feeds, package versions, auditing and signature settings unchanged.
rem No database command and no --apply command is executed.
rem Leave this file beside WazuhAuditImporter.sln. Run only one build at a time.

if /I not "%COMPUTERNAME%"=="MGMTNB08" (
    echo STOP: Run this pilot build on laptop MGMTNB08.
    exit /b 1
)
pushd "%~dp0" || exit /b 1
if not exist "WazuhAuditImporter.sln" (
    echo STOP: Put Restore-And-Preview.cmd beside WazuhAuditImporter.sln.
    goto setup_failed
)
if not exist "src\WazuhAuditImporter\WazuhAuditImporter.csproj" goto missing_files
if not exist "tests\WazuhAuditImporter.SelfTests\WazuhAuditImporter.SelfTests.csproj" goto missing_files
if not exist "samples\wazuh-delete-sample.json" goto missing_files
where dotnet.exe >nul 2>&1
if errorlevel 1 (
    echo STOP: dotnet.exe was not found. The solution targets .NET 9.
    goto setup_failed
)
if not defined LOCALAPPDATA (
    echo STOP: LOCALAPPDATA is not defined. No build was attempted.
    goto setup_failed
)

:new_workspace
set "WAI_RUN=%LOCALAPPDATA%\WaiNugetRecovery\%RANDOM%-%RANDOM%-%RANDOM%"
if exist "%WAI_RUN%" goto new_workspace
mkdir "%WAI_RUN%"
if errorlevel 1 goto workspace_failed
for %%D in (packages http scratch plugins temp) do (
    mkdir "%WAI_RUN%\%%D"
    if errorlevel 1 goto workspace_failed
)

rem All overrides are child-process-only, restored at batch exit by SETLOCAL.
rem Isolate packages AND cache/scratch together to avoid shared lock conflicts.
set "NUGET_PACKAGES=%WAI_RUN%\packages"
set "NUGET_HTTP_CACHE_PATH=%WAI_RUN%\http"
set "NUGET_SCRATCH=%WAI_RUN%\scratch"
set "NUGET_PLUGINS_CACHE_PATH=%WAI_RUN%\plugins"
set "TEMP=%WAI_RUN%\temp"
set "TMP=%WAI_RUN%\temp"
rem Preview never needs a database password. Do not expose this variable to MSBuild.
set "WAZUH_DB_PASSWORD="

echo.
echo SDK selected:
dotnet.exe --version
if errorlevel 1 goto setup_failed
echo.
echo Fresh cache and logs: "%WAI_RUN%"
echo Existing global caches will NOT be cleared.
echo No package-source or system security settings will be changed.
echo.

set "WAI_STAGE=NuGet restore"
set "WAI_STAGE_LOG=%WAI_RUN%\restore-diagnostic.log"
echo [1/4] Restoring dependencies. New downloads may take a few minutes.
echo Detailed output is being saved to "%WAI_STAGE_LOG%".
dotnet.exe restore "WazuhAuditImporter.sln" --packages "%NUGET_PACKAGES%" --disable-parallel --force --disable-build-servers --verbosity diagnostic --tl:off > "%WAI_STAGE_LOG%" 2>&1
if errorlevel 1 goto stage_failed
echo Restore succeeded.

set "WAI_STAGE=Build"
set "WAI_STAGE_LOG=%WAI_RUN%\build.log"
echo.
echo [2/4] Building the solution without another restore.
dotnet.exe build "WazuhAuditImporter.sln" --no-restore --disable-build-servers -m:1 --tl:off --verbosity minimal > "%WAI_STAGE_LOG%" 2>&1
if errorlevel 1 goto stage_failed
type "%WAI_STAGE_LOG%"

set "WAI_STAGE=Parser and scope self-tests"
set "WAI_STAGE_LOG=%WAI_RUN%\self-tests.log"
echo.
echo [3/4] Running offline self-tests. No MariaDB connection.
dotnet.exe run --project "tests\WazuhAuditImporter.SelfTests\WazuhAuditImporter.SelfTests.csproj" --no-build --no-restore > "%WAI_STAGE_LOG%" 2>&1
if errorlevel 1 goto stage_failed
type "%WAI_STAGE_LOG%"

set "WAI_STAGE=Sample preview"
set "WAI_STAGE_LOG=%WAI_RUN%\preview.log"
echo.
echo [4/4] Previewing the supplied event without database writes.
dotnet.exe run --project "src\WazuhAuditImporter\WazuhAuditImporter.csproj" --no-build --no-restore -- import "samples\wazuh-delete-sample.json" > "%WAI_STAGE_LOG%" 2>&1
if errorlevel 1 goto stage_failed
type "%WAI_STAGE_LOG%"

echo.
echo SUCCESS: restore, build, self-tests and preview completed.
echo No database connection or writes were requested by this script.
echo Keep the cache directory for now: the restored project references it.
echo Logs and cache: "%WAI_RUN%"
echo Do not publish complete diagnostic logs without checking for secrets.
popd
exit /b 0

:stage_failed
echo.
echo STOP: %WAI_STAGE% failed. Do not continue with --apply.
echo Full stage log: "%WAI_STAGE_LOG%"
echo.
echo --- Selected error context ---
powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$p=$env:WAI_STAGE_LOG; $m=Select-String -LiteralPath $p -Pattern 'Cannot create a file|:\s*error\b|\bFAIL:|System\.IO\.(IOException|DirectoryNotFoundException|FileNotFoundException)' -Context 3,10; if($m){$m | Select-Object -First 4 | Out-String -Width 180} else {Get-Content -LiteralPath $p -Tail 35}"
echo --- End error context ---
echo.
echo Review this excerpt for credentials before sharing it.
echo Do not upload the full diagnostic log or delete caches to retry.
popd
exit /b 1

:missing_files
echo STOP: The expected solution files are missing. Use the extracted project folder.
goto setup_failed

:workspace_failed
echo STOP: Could not create the private cache directories.
echo Attempted location: "%WAI_RUN%"
echo Existing caches and source files have not been deleted.

:setup_failed
popd
exit /b 1
