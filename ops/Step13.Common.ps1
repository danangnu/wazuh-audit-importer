Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Step13RepoRoot {
    param([string]$ScriptRoot = $PSScriptRoot)
    return (Split-Path -Parent $ScriptRoot)
}

function Get-Step13SettingsPath {
    param([string]$SettingsPath)
    if ([string]::IsNullOrWhiteSpace($SettingsPath)) {
        $SettingsPath = Join-Path $PSScriptRoot 'step13.local.json'
    }
    return [System.IO.Path]::GetFullPath($SettingsPath)
}

function Expand-Step13Value {
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return $null }
    return [Environment]::ExpandEnvironmentVariables($Value)
}

function Resolve-Step13Path {
    param(
        [Parameter(Mandatory=$true)][string]$RepoRoot,
        [AllowNull()][string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $expanded = Expand-Step13Value $Value
    if ([System.IO.Path]::IsPathRooted($expanded)) {
        return [System.IO.Path]::GetFullPath($expanded)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $expanded))
}

function Import-Step13Settings {
    param([string]$SettingsPath)
    $path = Get-Step13SettingsPath $SettingsPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Step 13 settings not found: $path. Copy ops\\step13.example.json to ops\\step13.local.json and review it first."
    }
    $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    $settings = $raw | ConvertFrom-Json
    $repo = Get-Step13RepoRoot

    $settings | Add-Member -NotePropertyName '_SettingsPath' -NotePropertyValue $path -Force
    $settings | Add-Member -NotePropertyName '_RepoRoot' -NotePropertyValue $repo -Force
    $settings.SshPrivateKey = Resolve-Step13Path $repo $settings.SshPrivateKey
    $settings.SshKnownHosts = Resolve-Step13Path $repo $settings.SshKnownHosts
    $settings.SecretDirectory = Resolve-Step13Path $repo $settings.SecretDirectory
    $settings.StateDir = Resolve-Step13Path $repo $settings.StateDir
    $settings.ReportDir = Resolve-Step13Path $repo $settings.ReportDir
    $settings.LogDirectory = Resolve-Step13Path $repo $settings.LogDirectory
    if (-not [string]::IsNullOrWhiteSpace([string]$settings.ConfigPath)) {
        $settings.ConfigPath = Resolve-Step13Path $repo $settings.ConfigPath
    }
    return $settings
}

function Test-Step13Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Step13Administrator {
    if (-not (Test-Step13Administrator)) {
        throw 'Run this PowerShell window as Administrator. Step 13 networking/task setup requires elevation.'
    }
}

function Test-Step13Ipv4Text {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Value, [ref]$ip)) { return $false }
    return $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
        $Value -notlike '127.*' -and $Value -notlike '169.254.*'
}

function Invoke-Step13BatchSshProbe {
    param(
        [Parameter(Mandatory=$true)]$Settings,
        [Parameter(Mandatory=$true)][string]$VmIp,
        [int]$TimeoutMs = 8000
    )

    $ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if ($null -eq $ssh) {
        return [pscustomobject]@{ Success = $false; ExitCode = $null; StdOut = ''; StdErr = 'ssh.exe not found.'; TimedOut = $false }
    }
    if (-not (Test-Path -LiteralPath ([string]$Settings.SshPrivateKey) -PathType Leaf)) {
        return [pscustomobject]@{ Success = $false; ExitCode = $null; StdOut = ''; StdErr = 'SSH private key not found.'; TimedOut = $false }
    }
    if (-not (Test-Path -LiteralPath ([string]$Settings.SshKnownHosts) -PathType Leaf)) {
        return [pscustomobject]@{ Success = $false; ExitCode = $null; StdOut = ''; StdErr = 'Pinned known_hosts not found.'; TimedOut = $false }
    }

    # Windows PowerShell 5.1 can leave a directly-invoked native ssh.exe attached
    # to this console's stdin. Use -n/-T plus a bounded child process so a preflight
    # can never wait forever on SSH even when OpenSSH behaves unexpectedly.
    $tokens = @(
        '-n','-T',
        '-o','BatchMode=yes',
        '-o','PasswordAuthentication=no',
        '-o','KbdInteractiveAuthentication=no',
        '-o','NumberOfPasswordPrompts=0',
        '-o','ConnectionAttempts=1',
        '-o','ConnectTimeout=5',
        '-o','ServerAliveInterval=3',
        '-o','ServerAliveCountMax=1',
        '-o',"UserKnownHostsFile=$($Settings.SshKnownHosts)",
        '-o','HostKeyAlias=WAZUH-LAB',
        '-o','StrictHostKeyChecking=yes',
        '-i',[string]$Settings.SshPrivateKey,
        "$($Settings.SshUser)@$VmIp",
        'echo STEP13_SSH_OK'
    )

    $quote = {
        param([string]$Value)
        return '"' + ($Value -replace '"','\"') + '"'
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ssh.Source
    $psi.Arguments = (($tokens | ForEach-Object { & $quote ([string]$_) }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    try {
        if (-not $p.Start()) {
            return [pscustomobject]@{ Success = $false; ExitCode = $null; StdOut = ''; StdErr = 'ssh.exe failed to start.'; TimedOut = $false }
        }
        try { $p.StandardInput.Close() } catch { }
        if (-not $p.WaitForExit($TimeoutMs)) {
            try { $p.Kill() } catch { }
            try { $p.WaitForExit(2000) | Out-Null } catch { }
            return [pscustomobject]@{ Success = $false; ExitCode = $null; StdOut = ''; StdErr = "SSH probe timed out after $TimeoutMs ms."; TimedOut = $true }
        }
        $stdout = $p.StandardOutput.ReadToEnd().Trim()
        $stderr = $p.StandardError.ReadToEnd().Trim()
        $ok = ($p.ExitCode -eq 0 -and $stdout -match '(^|\s)STEP13_SSH_OK($|\s)')
        return [pscustomobject]@{ Success = $ok; ExitCode = $p.ExitCode; StdOut = $stdout; StdErr = $stderr; TimedOut = $false }
    }
    catch {
        return [pscustomobject]@{ Success = $false; ExitCode = $null; StdOut = ''; StdErr = $_.Exception.Message; TimedOut = $false }
    }
    finally {
        try { $p.Dispose() } catch { }
    }
}

function Test-Step13PinnedSshCandidate {
    param(
        [Parameter(Mandatory=$true)]$Settings,
        [Parameter(Mandatory=$true)][string]$VmIp
    )
    $probe = Invoke-Step13BatchSshProbe -Settings $Settings -VmIp $VmIp -TimeoutMs 6000
    return [bool]$probe.Success
}

function Get-Step13VmIpv4 {
    param([Parameter(Mandatory=$true)]$Settings)
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        throw 'Hyper-V PowerShell module is unavailable. Enable Hyper-V management tools first.'
    }
    $vm = Get-VM -Name ([string]$Settings.VmName) -ErrorAction Stop
    if ($vm.State -ne 'Running') { return $null }

    $prefix = [string]$Settings.VmIpv4Prefix

    # 1) Preferred source: Hyper-V KVP / integration-services reporting.
    $addresses = @(
        Get-VMNetworkAdapter -VMName ([string]$Settings.VmName) -ErrorAction Stop |
            ForEach-Object { $_.IPAddresses } |
            Where-Object { Test-Step13Ipv4Text ([string]$_) }
    )
    if (-not [string]::IsNullOrWhiteSpace($prefix)) {
        $preferred = @($addresses | Where-Object { $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
        if ($preferred.Count -gt 0) { return [string]$preferred[0] }
    }
    if ($addresses.Count -gt 0) { return [string]$addresses[0] }

    # 2) Optional operator override. Useful while Hyper-V reports KVP "No Contact".
    $override = $null
    if ($Settings.PSObject.Properties.Name -contains 'VmIpv4Override') {
        $override = [string]$Settings.VmIpv4Override
    }
    if (Test-Step13Ipv4Text $override) {
        if ([string]::IsNullOrWhiteSpace($prefix) -or $override.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            if (Test-Step13Tcp $override 22 1200) { return $override }
        }
    }

    # 3) Recover from an existing pilot portproxy target, but only if it is live.
    $candidates = New-Object System.Collections.Generic.List[string]
    try {
        $raw = & netsh interface portproxy show v4tov4 2>$null
        foreach ($line in $raw) {
            if ($line -match '^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*$') {
                $candidate = [string]$Matches[3]
                $connectPort = [int]$Matches[4]
                if ($connectPort -in @(443,1514,1515) -and (Test-Step13Ipv4Text $candidate)) {
                    if ([string]::IsNullOrWhiteSpace($prefix) -or $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                        if (-not $candidates.Contains($candidate)) { $candidates.Add($candidate) }
                    }
                }
            }
        }
    } catch { }

    # 4) Hyper-V Default Switch fallback: inspect the host neighbour table. A Wazuh
    #    candidate must expose SSH + dashboard + agent + enrolment ports. After SSH
    #    initialization, the pinned host key is used to disambiguate candidates.
    try {
        if (Get-Command Get-NetNeighbor -ErrorAction SilentlyContinue) {
            $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { Test-Step13Ipv4Text ([string]$_.IPAddress) }
            foreach ($n in $neighbors) {
                $candidate = [string]$n.IPAddress
                if (-not [string]::IsNullOrWhiteSpace($prefix) -and -not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
                if (-not $candidates.Contains($candidate)) { $candidates.Add($candidate) }
            }
        }
    } catch { }

    $live = @()
    foreach ($candidate in @($candidates)) {
        if ((Test-Step13Tcp $candidate 22 800) -and
            (Test-Step13Tcp $candidate 443 800) -and
            (Test-Step13Tcp $candidate 1514 800) -and
            (Test-Step13Tcp $candidate 1515 800)) {
            $live += $candidate
        }
    }

    if ($live.Count -eq 1) { return [string]$live[0] }
    if ($live.Count -gt 1) {
        foreach ($candidate in $live) {
            if (Test-Step13PinnedSshCandidate $Settings $candidate) { return [string]$candidate }
        }
    }
    return $null
}

function Get-Step13SecretFile {
    param([Parameter(Mandatory=$true)]$Settings, [Parameter(Mandatory=$true)][ValidateSet('db','indexer')] [string]$Kind)
    $name = if ($Kind -eq 'db') { 'db-password.dpapi' } else { 'indexer-password.dpapi' }
    return Join-Path ([string]$Settings.SecretDirectory) $name
}

function Read-Step13DpapiSecret {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Secret file not found: $Path"
    }
    $cipher = (Get-Content -LiteralPath $Path -Raw -Encoding UTF8).Trim()
    if ([string]::IsNullOrWhiteSpace($cipher)) { throw "Secret file is empty: $Path" }
    $secure = ConvertTo-SecureString $cipher
    $cred = New-Object System.Management.Automation.PSCredential('x', $secure)
    return $cred.GetNetworkCredential().Password
}

function Write-Step13Health {
    param(
        [Parameter(Mandatory=$true)]$Settings,
        [Parameter(Mandatory=$true)]$Payload
    )
    $root = Split-Path -Parent ([string]$Settings.LogDirectory)
    if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force | Out-Null }
    $path = Join-Path $root 'step13-health.json'
    $tmp = "$path.tmp"
    $Payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $path -Force
    return $path
}

function Test-Step13Tcp {
    param([Parameter(Mandatory=$true)][string]$ComputerName,[Parameter(Mandatory=$true)][int]$Port,[int]$TimeoutMs=2500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($ar)
        return $true
    }
    catch { return $false }
    finally { $client.Dispose() }
}

function Get-Step13DotnetDll {
    param([Parameter(Mandatory=$true)]$Settings)
    return Join-Path ([string]$Settings._RepoRoot) 'src\WazuhAuditImporter\bin\Debug\net9.0\WazuhAuditImporter.dll'
}
