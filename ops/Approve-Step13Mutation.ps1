param(
    [Parameter(Mandatory=$true)][ValidateRange(1,[long]::MaxValue)][long]$MutationId,
    [string]$SettingsPath
)

. "$PSScriptRoot\Step13.Common.ps1"
$settings = Import-Step13Settings $SettingsPath
$dll = Get-Step13DotnetDll $settings
if (-not (Test-Path -LiteralPath $dll)) { throw "Built importer DLL not found: $dll" }

$statePath = Join-Path ([string]$settings.StateDir) 'step12-pipeline-state.json'
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    throw "Pipeline state file not found: $statePath"
}
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$approvedState = $null
if ($null -ne $state.Candidates) {
    $approvedState = @($state.Candidates) | Where-Object {
        [string]$_.Stage -eq 'ReadyForApproval' -and [long]$_.MutationId -eq $MutationId
    } | Select-Object -First 1
    if ($null -eq $approvedState) {
        $ready = @($state.Candidates) | Where-Object { [string]$_.Stage -eq 'ReadyForApproval' } | ForEach-Object { [string]$_.MutationId }
        throw "Mutation $MutationId is not currently ReadyForApproval. Ready mutation(s): $($ready -join ',')."
    }
} else {
    if ([string]$state.Stage -ne 'ReadyForApproval') {
        throw "Pipeline is not ReadyForApproval. Current stage: $($state.Stage)."
    }
    if ([long]$state.MutationId -ne $MutationId) {
        throw "Requested mutation $MutationId does not match current ReadyForApproval mutation $($state.MutationId)."
    }
}

$dbPassword = Read-Step13DpapiSecret (Get-Step13SecretFile $settings 'db')
$env:WAZUH_DB_PASSWORD = $dbPassword
try {
    $common = @(
        $dll,'solr-execute','--mutation-id',$MutationId,
        '--worker-root',[string]$settings.WorkerRoot,
        '--db-user',[string]$settings.DbUser
    )
    if (-not [string]::IsNullOrWhiteSpace([string]$settings.ConfigPath)) { $common += @('--config',[string]$settings.ConfigPath) }

    Write-Host "Running fresh Step 11 preflight for mutation $MutationId..."
    & dotnet @common
    if ($LASTEXITCODE -ne 0) { throw "Step 11 preflight failed with exit code $LASTEXITCODE. No apply attempted." }

    Write-Host ''
    Write-Host 'This is the manual Solr write boundary.' -ForegroundColor Yellow
    Write-Host "Type APPLY-$MutationId to execute the reviewed mutation, commit, and verify it."
    $confirm = Read-Host 'Confirmation'
    if ($confirm -ne "APPLY-$MutationId") {
        Write-Host 'Approval cancelled. No Solr write requested.'
        exit 1
    }

    & dotnet @common --apply
    if ($LASTEXITCODE -ne 0) {
        throw "Step 11 apply returned exit code $LASTEXITCODE. Treat Solr state as uncertain until read-only verification."
    }

    Write-Host ''
    Write-Host 'Running post-apply read-only candidate comparison...'
    $readArgs = @(
        $dll,'solr-readonly','--worker-root',[string]$settings.WorkerRoot,
        '--report-dir',[string]$settings.ReportDir
    )
    if (-not [string]::IsNullOrWhiteSpace([string]$settings.ConfigPath)) { $readArgs += @('--config',[string]$settings.ConfigPath) }
    & dotnet @readArgs
    if ($LASTEXITCODE -ne 0) { throw "Post-apply solr-readonly returned exit code $LASTEXITCODE." }
}
finally {
    $env:WAZUH_DB_PASSWORD = $null
    $dbPassword = $null
}
