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
$configPath = Join-Path $repo 'importer.step15.pilot.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw "Step 15 importer config not found: $configPath" }

$expected = @(
    '1180000','1180001','1180002','1180003','1180004','1180005','1180006','1180007','1180008','1180009',
    '1180010','1180011','1180012','1180013','1180014','1180015','1180016','1180017','1180018','1180019',
    '1180020','1180021','1180022','1180023','1180097'
)
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$actual = @($config.CandidateIds)
if ($actual.Count -ne 25 -or ($actual -join ',') -ne ($expected -join ',')) {
    throw "Unexpected Step 15 CandidateIds: $($actual -join ',')"
}

$settings = Get-Content -LiteralPath $SettingsPath -Raw | ConvertFrom-Json
$taskName = [string]$settings.TaskName
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
}
& (Join-Path $PSScriptRoot 'Stop-Step13.ps1') -SettingsPath $SettingsPath
Start-Sleep -Seconds 2
$settings.ConfigPath = [System.IO.Path]::GetFullPath($configPath)
$settings | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $SettingsPath -Encoding UTF8
Write-Host "Step 13 ConfigPath now points to Step 15 controlled 25-candidate config: $($settings.ConfigPath)"
Write-Host "Active allowlist count: $($expected.Count)"
Write-Host "Active allowlist: $($expected -join ',')"
Write-Host 'Baseline enrollment gate remains mandatory. Existing APPROVED baselines are preserved; newly added candidates must be captured/reviewed before action planning.'

if ($StartTask) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Start-ScheduledTask -TaskName $taskName
        Write-Host "Scheduled task start requested: $taskName"
    } else {
        Write-Host "Scheduled task is not installed: $taskName" -ForegroundColor Yellow
    }
} else {
    Write-Host 'Scheduled task was not started. First apply the matching 25-candidate FIM allowlist on FLOSVR01, capture baselines, then start Step 13.'
}
