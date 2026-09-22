@echo off
setlocal
pushd "%~dp0" || exit /b 1
where dotnet >nul 2>&1
if errorlevel 1 (
    echo ERROR: dotnet was not found. This solution requires the .NET 9 SDK.
    popd
    exit /b 1
)
dotnet restore WazuhAuditImporter.sln
if errorlevel 1 goto failed
dotnet build WazuhAuditImporter.sln --no-restore
if errorlevel 1 goto failed
dotnet run --project tests\WazuhAuditImporter.SelfTests --no-build
if errorlevel 1 goto failed
dotnet run --project src\WazuhAuditImporter --no-build -- import samples\wazuh-delete-sample.json
if errorlevel 1 goto failed
echo.
echo Preview completed. This script did not connect to MariaDB or write data.
popd
exit /b 0
:failed
echo.
echo STOP: a restore, build, self-test or preview step failed. Do not proceed with --apply.
popd
exit /b 1
