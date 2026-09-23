param([string]$SettingsPath)

. "$PSScriptRoot\Step13.Common.ps1"
Assert-Step13Administrator
$settings = Import-Step13Settings $SettingsPath
$settingsPathResolved = [string]$settings._SettingsPath
$repo = [string]$settings._RepoRoot
$dll = Get-Step13DotnetDll $settings
if (-not (Test-Path -LiteralPath $dll -PathType Leaf)) {
    throw "Built importer DLL not found: $dll. Run Restore-And-Preview.cmd first."
}

New-Item -ItemType Directory -Path ([string]$settings.LogDirectory) -Force | Out-Null
New-Item -ItemType Directory -Path ([string]$settings.StateDir) -Force | Out-Null
New-Item -ItemType Directory -Path ([string]$settings.ReportDir) -Force | Out-Null

$dbSecretPath = Get-Step13SecretFile $settings 'db'
$indexerSecretPath = Get-Step13SecretFile $settings 'indexer'
$dbPassword = Read-Step13DpapiSecret $dbSecretPath
$indexerPassword = Read-Step13DpapiSecret $indexerSecretPath
$env:WAZUH_DB_PASSWORD = $dbPassword
$env:WAZUH_INDEXER_PASSWORD = $indexerPassword

$mutexName = 'WazuhAuditImporter-Step13-' + ($env:USERNAME -replace '[^A-Za-z0-9_.-]','_')
$mutex = New-Object System.Threading.Mutex($false, $mutexName)
if (-not $mutex.WaitOne(0, $false)) { throw 'Another Step 13 supervisor is already running for this Windows user.' }

$pipelineProcess = $null
$tunnelProcess = $null
$currentVmIp = $null
$pipelineRestarts = 0
$tunnelRestarts = 0
$lastError = $null
$lastPipelineOut = $null
$lastPipelineErr = $null
$lastTunnelErr = $null
$runnerPid = $PID

function Quote-Arg([string]$Value) {
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + ($Value -replace '"','\"') + '"'
}

function Stop-ChildProcess($Process) {
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            try { $Process.WaitForExit(5000) | Out-Null } catch { }
        }
    } catch { }
}

function Start-Step13Tunnel([string]$VmIp) {
    $ssh = (Get-Command ssh.exe -ErrorAction Stop).Source
    if (-not (Test-Path -LiteralPath ([string]$settings.SshPrivateKey) -PathType Leaf)) {
        throw "SSH private key missing: $($settings.SshPrivateKey). Run Initialize-Step13Ssh.ps1."
    }
    if (-not (Test-Path -LiteralPath ([string]$settings.SshKnownHosts) -PathType Leaf)) {
        throw "Pinned SSH known_hosts missing: $($settings.SshKnownHosts). Run Initialize-Step13Ssh.ps1."
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outFile = Join-Path ([string]$settings.LogDirectory) "ssh-tunnel-$stamp.out.log"
    $errFile = Join-Path ([string]$settings.LogDirectory) "ssh-tunnel-$stamp.err.log"
    $local = "$($settings.TunnelListenAddress):$($settings.TunnelPort):127.0.0.1:9200"
    $parts = @(
        '-N','-T',
        '-o','BatchMode=yes',
        '-o','ExitOnForwardFailure=yes',
        '-o','ConnectTimeout=8',
        '-o','ServerAliveInterval=30',
        '-o','ServerAliveCountMax=3',
        '-o',"UserKnownHostsFile=$($settings.SshKnownHosts)",
        '-o','HostKeyAlias=WAZUH-LAB',
        '-o','StrictHostKeyChecking=yes',
        '-i',[string]$settings.SshPrivateKey,
        '-L',$local,
        "$($settings.SshUser)@$VmIp"
    )
    $argLine = ($parts | ForEach-Object { Quote-Arg ([string]$_) }) -join ' '
    $p = Start-Process -FilePath $ssh -ArgumentList $argLine -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    do {
        if ($p.HasExited) {
            $tail = if (Test-Path $errFile) { (Get-Content $errFile -Tail 10) -join ' | ' } else { '' }
            throw "SSH tunnel exited before local port opened. $tail"
        }
        if (Test-Step13Tcp ([string]$settings.TunnelListenAddress) ([int]$settings.TunnelPort) 500) {
            $script:lastTunnelErr = $errFile
            return $p
        }
        Start-Sleep -Milliseconds 400
    } while ([DateTime]::UtcNow -lt $deadline)
    Stop-ChildProcess $p
    throw "SSH tunnel did not open $($settings.TunnelListenAddress):$($settings.TunnelPort) within 12 seconds."
}

function Start-Step13Pipeline {
    $dotnet = (Get-Command dotnet.exe -ErrorAction SilentlyContinue)
    if ($null -eq $dotnet) { $dotnet = Get-Command dotnet -ErrorAction Stop }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outFile = Join-Path ([string]$settings.LogDirectory) "pipeline-$stamp.out.log"
    $errFile = Join-Path ([string]$settings.LogDirectory) "pipeline-$stamp.err.log"
    $parts = @(
        $dll,
        'pipeline',
        '--db-user',[string]$settings.DbUser,
        '--indexer-user',[string]$settings.IndexerUser,
        '--worker-root',[string]$settings.WorkerRoot,
        '--state-dir',[string]$settings.StateDir,
        '--report-dir',[string]$settings.ReportDir
    )
    if (-not [string]::IsNullOrWhiteSpace([string]$settings.ConfigPath)) {
        $parts += @('--config',[string]$settings.ConfigPath)
    }
    $argLine = ($parts | ForEach-Object { Quote-Arg ([string]$_) }) -join ' '
    $p = Start-Process -FilePath $dotnet.Source -ArgumentList $argLine -PassThru -WindowStyle Hidden `
        -WorkingDirectory $repo -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $script:lastPipelineOut = $outFile
    $script:lastPipelineErr = $errFile
    return $p
}

function Save-Health([string]$Status) {
    $pipelineRunning = $false
    $tunnelRunning = $false
    try { $pipelineRunning = ($null -ne $pipelineProcess -and -not $pipelineProcess.HasExited) } catch { }
    try { $tunnelRunning = ($null -ne $tunnelProcess -and -not $tunnelProcess.HasExited) } catch { }
    $tunnelOpen = Test-Step13Tcp ([string]$settings.TunnelListenAddress) ([int]$settings.TunnelPort) 400
    $payload = [ordered]@{
        schema_version = 1
        status = $Status
        updated_utc = [DateTime]::UtcNow.ToString('o')
        runner_pid = $runnerPid
        vm_name = [string]$settings.VmName
        vm_ip = $currentVmIp
        tunnel_open = $tunnelOpen
        tunnel_pid = if ($tunnelRunning) { $tunnelProcess.Id } else { $null }
        pipeline_running = $pipelineRunning
        pipeline_pid = if ($pipelineRunning) { $pipelineProcess.Id } else { $null }
        pipeline_restarts = $pipelineRestarts
        tunnel_restarts = $tunnelRestarts
        last_error = $lastError
        pipeline_stdout = $lastPipelineOut
        pipeline_stderr = $lastPipelineErr
        tunnel_stderr = $lastTunnelErr
        state_file = (Join-Path ([string]$settings.StateDir) 'step12-pipeline-state.json')
        settings_file = $settingsPathResolved
    }
    Write-Step13Health $settings $payload | Out-Null
}

try {
    Write-Host 'Step 13 supervisor started.'
    Write-Host "VM       : $($settings.VmName)"
    Write-Host "Worker   : $($settings.WorkerRoot)"
    Write-Host "State    : $($settings.StateDir)"
    Write-Host 'Solr     : approval-gated; this supervisor NEVER invokes solr-execute --apply.'

    while ($true) {
        try {
            $vmIp = Get-Step13VmIpv4 $settings
            if ([string]::IsNullOrWhiteSpace($vmIp)) {
                $lastError = "VM '$($settings.VmName)' is stopped or has no visible IPv4 address. Waiting."
                if ($null -ne $tunnelProcess) { Stop-ChildProcess $tunnelProcess; $tunnelProcess = $null }
                Save-Health 'waiting_for_vm'
                Start-Sleep -Seconds ([int]$settings.RunnerPollSeconds)
                continue
            }

            $needTunnel = $false
            if ($currentVmIp -ne $vmIp) { $needTunnel = $true }
            if ($null -eq $tunnelProcess) { $needTunnel = $true }
            elseif ($tunnelProcess.HasExited) { $needTunnel = $true }
            elseif (-not (Test-Step13Tcp ([string]$settings.TunnelListenAddress) ([int]$settings.TunnelPort) 500)) { $needTunnel = $true }

            if ($needTunnel) {
                if ($null -ne $tunnelProcess) { Stop-ChildProcess $tunnelProcess; $tunnelProcess = $null }
                $currentVmIp = $vmIp
                & "$PSScriptRoot\Repair-WazuhLabNetwork.ps1" -SettingsPath $settingsPathResolved | Out-Host
                $tunnelProcess = Start-Step13Tunnel $currentVmIp
                $tunnelRestarts++
            }

            if ($null -eq $pipelineProcess -or $pipelineProcess.HasExited) {
                if ($null -ne $pipelineProcess) {
                    $pipelineRestarts++
                    Start-Sleep -Seconds ([int]$settings.RunnerRestartDelaySeconds)
                }
                if (-not (Test-Step13Tcp ([string]$settings.TunnelListenAddress) ([int]$settings.TunnelPort) 800)) {
                    throw 'Indexer tunnel is not ready; refusing to start pipeline yet.'
                }
                $pipelineProcess = Start-Step13Pipeline
                Start-Sleep -Seconds ([int]$settings.PipelineStartupGraceSeconds)
                if ($pipelineProcess.HasExited) {
                    $tail = if (Test-Path $lastPipelineErr) { (Get-Content $lastPipelineErr -Tail 20) -join ' | ' } else { '' }
                    throw "Pipeline exited during startup. $tail"
                }
            }

            $lastError = $null
            Save-Health 'running'
        }
        catch {
            $lastError = $_.Exception.Message
            Save-Health 'degraded'
        }
        Start-Sleep -Seconds ([int]$settings.RunnerPollSeconds)
    }
}
finally {
    Save-Health 'stopping'
    Stop-ChildProcess $pipelineProcess
    Stop-ChildProcess $tunnelProcess
    $env:WAZUH_DB_PASSWORD = $null
    $env:WAZUH_INDEXER_PASSWORD = $null
    $dbPassword = $null
    $indexerPassword = $null
    try { $mutex.ReleaseMutex() } catch { }
    $mutex.Dispose()
}
