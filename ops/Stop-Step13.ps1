param([string]$SettingsPath)

. "$PSScriptRoot\Step13.Common.ps1"
Assert-Step13Administrator
$settings = Import-Step13Settings $SettingsPath
Stop-ScheduledTask -TaskName ([string]$settings.TaskName) -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$healthPath = Join-Path (Split-Path -Parent ([string]$settings.LogDirectory)) 'step13-health.json'
if (Test-Path -LiteralPath $healthPath) {
    try {
        $h = Get-Content -LiteralPath $healthPath -Raw | ConvertFrom-Json
        foreach ($pidValue in @($h.pipeline_pid,$h.tunnel_pid,$h.runner_pid)) {
            if ($pidValue) {
                $p = Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue
                if ($p -and $p.ProcessName -in @('dotnet','ssh','powershell','pwsh')) {
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch { Write-Warning $_.Exception.Message }
}
Write-Host 'Step 13 scheduled task/processes stopped. No Solr mutation was applied by this script.'
