param(
    [string]$SettingsPath,
    [switch]$StartNow
)

. "$PSScriptRoot\Step13.Common.ps1"
Assert-Step13Administrator
$settings = Import-Step13Settings $SettingsPath
$settingsPathResolved = [string]$settings._SettingsPath

# Run preflight in a CHILD PowerShell process. Step13-Preflight.ps1 intentionally uses
# exit codes for direct/CLI use; invoking it with & in this host would terminate this
# installer before Register-ScheduledTask is reached.
$preflightScript = Join-Path $PSScriptRoot 'Step13-Preflight.ps1'
$preflightArgs = @(
    '-NoProfile',
    '-ExecutionPolicy','Bypass',
    '-File', $preflightScript,
    '-SettingsPath', $settingsPathResolved
)
$preflightProcess = Start-Process -FilePath 'PowerShell.exe' -ArgumentList $preflightArgs `
    -Wait -PassThru -NoNewWindow
if ($preflightProcess.ExitCode -ne 0) {
    throw "Step 13 preflight failed with exit code $($preflightProcess.ExitCode). Scheduled task was not installed."
}

$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$runner = Join-Path $PSScriptRoot 'Step13-Run.ps1'
$hostExe = (Get-Process -Id $PID).Path
$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$runner`" -SettingsPath `"$settingsPathResolved`""
$action = New-ScheduledTaskAction -Execute $hostExe -Argument $arguments -WorkingDirectory ([string]$settings._RepoRoot)
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$taskSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $taskSettings `
    -Description 'Allied Wazuh-to-Solr Step 13 approval-gated supervisor. Maintains dynamic WAZUH-LAB forwarding/tunnel and Step 12 pipeline. Never auto-applies Solr mutations.'
Register-ScheduledTask -TaskName ([string]$settings.TaskName) -InputObject $task -Force | Out-Null

Write-Host "Installed scheduled task: $($settings.TaskName)"
Write-Host "User: $user"
Write-Host 'Trigger: at logon, highest privileges, one instance.'
Write-Host 'Solr apply remains manual; the task only runs approval-gated Step 12 orchestration.'

if ($StartNow) {
    Start-ScheduledTask -TaskName ([string]$settings.TaskName)
    Start-Sleep -Seconds 3
    Write-Host 'Task started.'
}
