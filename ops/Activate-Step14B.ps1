param(
    [string]$SettingsPath,
    [switch]$StartTask
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\Step13.Common.ps1"
Assert-Step13Administrator
$repo = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SettingsPath)) { $SettingsPath = Join-Path $PSScriptRoot 'step13.local.json' }
$SettingsPath = [System.IO.Path]::GetFullPath($SettingsPath)
if (-not (Test-Path -LiteralPath $SettingsPath -PathType Leaf)) { throw "Step 13 local settings not found: $SettingsPath" }
$configPath = Join-Path $repo 'importer.step14b.pilot.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Step 14B importer config not found: $configPath" }

$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$expected = @('1180000','1180001','1180002','1180003','1180097')
$actual = @($config.CandidateIds)
if (($actual -join ',') -ne ($expected -join ',')) { throw "Unexpected Step 14B CandidateIds: $($actual -join ',')" }

$settings = Get-Content -LiteralPath $SettingsPath -Raw | ConvertFrom-Json
$taskName = [string]$settings.TaskName
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
}
& (Join-Path $PSScriptRoot 'Stop-Step13.ps1') -SettingsPath $SettingsPath
Start-Sleep -Seconds 2
$settings.ConfigPath = [System.IO.Path]::GetFullPath($configPath)
$settings | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $SettingsPath -Encoding UTF8
Write-Host "Step 13 ConfigPath now points to Step 14B pilot config: $($settings.ConfigPath)"
Write-Host "Active allowlist: $($expected -join ',')"

if ($StartTask) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Start-ScheduledTask -TaskName $taskName
        Write-Host "Scheduled task start requested: $taskName"
    } else {
        Write-Host "Scheduled task is not installed: $taskName" -ForegroundColor Yellow
    }
} else {
    Write-Host 'Scheduled task was not started. First apply the matching FIM allowlist on FLOSVR01, then start Step 13.'
}
