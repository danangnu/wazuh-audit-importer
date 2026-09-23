param(
    [string]$SettingsPath,
    [switch]$SkipSshPublicKeyInstall
)

. "$PSScriptRoot\Step13.Common.ps1"
Assert-Step13Administrator
if ([string]::IsNullOrWhiteSpace($SettingsPath)) {
    $SettingsPath = Join-Path $PSScriptRoot 'step13.local.json'
}
$SettingsPath = [System.IO.Path]::GetFullPath($SettingsPath)
if (-not (Test-Path -LiteralPath $SettingsPath -PathType Leaf)) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'step13.example.json') -Destination $SettingsPath
    Write-Host "Created local Step 13 settings: $SettingsPath"
    Write-Host 'Defaults match the current MGMTNB08 / WAZUH-LAB / FLOSVR01 pilot. Review the file if your paths/users differ.'
}

& "$PSScriptRoot\Initialize-Step13Secrets.ps1" -SettingsPath $SettingsPath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& "$PSScriptRoot\Initialize-Step13Ssh.ps1" -SettingsPath $SettingsPath -SkipPublicKeyInstall:$SkipSshPublicKeyInstall
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& "$PSScriptRoot\Repair-WazuhLabNetwork.ps1" -SettingsPath $SettingsPath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ''
Write-Host 'Local Step 13 initialization complete.' -ForegroundColor Green
Write-Host 'NEXT, run ops\FLOSVR01-Use-MGMTNB08-Hostname.ps1 ON FLOSVR01 once so the Wazuh agent no longer depends on the laptop DHCP address.'
Write-Host 'Then return to MGMTNB08 and run .\Step13-Preflight.cmd.'
