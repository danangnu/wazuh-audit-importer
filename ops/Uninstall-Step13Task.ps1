param([string]$SettingsPath)

. "$PSScriptRoot\Step13.Common.ps1"
Assert-Step13Administrator
$settings = Import-Step13Settings $SettingsPath
& "$PSScriptRoot\Stop-Step13.ps1" -SettingsPath ([string]$settings._SettingsPath)
Unregister-ScheduledTask -TaskName ([string]$settings.TaskName) -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Removed scheduled task: $($settings.TaskName)"
Write-Host 'DPAPI secrets, SSH key, logs and MariaDB data were intentionally left untouched.'
