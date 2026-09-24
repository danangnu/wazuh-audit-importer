param(
    [string]$SettingsPath,
    [int]$Tail = 12
)

. "$PSScriptRoot\Step13.Common.ps1"
$settings = Import-Step13Settings $SettingsPath
Write-Host '=== Step 13 operational status ==='
$task = Get-ScheduledTask -TaskName ([string]$settings.TaskName) -ErrorAction SilentlyContinue
if ($null -eq $task) {
    Write-Host "Scheduled task : NOT INSTALLED ($($settings.TaskName))"
} else {
    Write-Host "Scheduled task : $($task.State) ($($settings.TaskName))"
}

$healthPath = Join-Path (Split-Path -Parent ([string]$settings.LogDirectory)) 'step13-health.json'
if (Test-Path -LiteralPath $healthPath -PathType Leaf) {
    $h = Get-Content -LiteralPath $healthPath -Raw | ConvertFrom-Json
    Write-Host "Supervisor      : $($h.status) pid=$($h.runner_pid)"
    Write-Host "WAZUH-LAB       : $($h.vm_ip)"
    Write-Host "SSH tunnel      : open=$($h.tunnel_open) pid=$($h.tunnel_pid)"
    Write-Host "Pipeline        : running=$($h.pipeline_running) pid=$($h.pipeline_pid) restarts=$($h.pipeline_restarts)"
    Write-Host "Updated UTC     : $($h.updated_utc)"
    if ($h.last_error) { Write-Host "Last error      : $($h.last_error)" -ForegroundColor Yellow }
    if ($Tail -gt 0 -and $h.pipeline_stdout -and (Test-Path -LiteralPath $h.pipeline_stdout)) {
        Write-Host ''
        Write-Host "--- latest pipeline output ($Tail lines) ---"
        Get-Content -LiteralPath $h.pipeline_stdout -Tail $Tail
    }
    if ($Tail -gt 0 -and $h.pipeline_stderr -and (Test-Path -LiteralPath $h.pipeline_stderr)) {
        $err = @(Get-Content -LiteralPath $h.pipeline_stderr -Tail $Tail)
        if ($err.Count -gt 0) {
            Write-Host ''
            Write-Host "--- latest pipeline stderr ($Tail lines) ---" -ForegroundColor Yellow
            $err
        }
    }
} else {
    Write-Host "Health file     : not created yet ($healthPath)"
}

$statePath = Join-Path ([string]$settings.StateDir) 'step12-pipeline-state.json'
if (Test-Path -LiteralPath $statePath -PathType Leaf) {
    $s = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    Write-Host ''
    Write-Host "Pipeline stage  : $($s.Stage)"
    Write-Host "Mutation        : $($s.MutationId)"
    Write-Host "Worker version  : $($s.WorkerVersion)"
    Write-Host "Detail          : $($s.Detail)"
    if ($null -ne $s.Candidates) {
        Write-Host "Candidate states:"
        foreach ($c in @($s.Candidates)) {
            Write-Host ("  {0}: {1} mutation={2} version={3}" -f $c.CandidateId,$c.Stage,$c.MutationId,$c.WorkerVersion)
        }
    }
    Write-Host "State updated   : $($s.UpdatedAtUtc)"
} else {
    Write-Host "Pipeline state  : not created yet ($statePath)"
}
