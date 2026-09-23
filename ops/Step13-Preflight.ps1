param([string]$SettingsPath)

. "$PSScriptRoot\Step13.Common.ps1"
$settings = Import-Step13Settings $SettingsPath
$failures = New-Object System.Collections.Generic.List[string]

function Check([string]$Name,[bool]$Ok,[string]$Detail) {
    $state = if ($Ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1}: {2}" -f $state,$Name,$Detail)
    if (-not $Ok) { $script:failures.Add("$Name - $Detail") }
}

Check 'Administrator' (Test-Step13Administrator) 'Step 13 supervisor/task requires elevation.'
$dll = Get-Step13DotnetDll $settings
Check 'Built importer' (Test-Path -LiteralPath $dll -PathType Leaf) $dll
Check 'Worker root' (Test-Path -LiteralPath ([string]$settings.WorkerRoot) -PathType Container) ([string]$settings.WorkerRoot)
Check 'MariaDB TCP' (Test-Step13Tcp '127.0.0.1' 3306 2000) '127.0.0.1:3306'
Check 'Solr TCP' (Test-Step13Tcp '192.168.18.22' 8983 2500) '192.168.18.22:8983'

$dbPath = Get-Step13SecretFile $settings 'db'
$ixPath = Get-Step13SecretFile $settings 'indexer'
$dbOk = $false; $ixOk = $false
try { $v = Read-Step13DpapiSecret $dbPath; $dbOk = -not [string]::IsNullOrEmpty($v); $v = $null } catch { }
try { $v = Read-Step13DpapiSecret $ixPath; $ixOk = -not [string]::IsNullOrEmpty($v); $v = $null } catch { }
Check 'DB DPAPI secret' $dbOk $dbPath
Check 'Indexer DPAPI secret' $ixOk $ixPath
Check 'SSH private key' (Test-Path -LiteralPath ([string]$settings.SshPrivateKey) -PathType Leaf) ([string]$settings.SshPrivateKey)
Check 'Pinned known_hosts' (Test-Path -LiteralPath ([string]$settings.SshKnownHosts) -PathType Leaf) ([string]$settings.SshKnownHosts)

$vmIp = $null
try { $vmIp = Get-Step13VmIpv4 $settings } catch { $failures.Add('Hyper-V - ' + $_.Exception.Message) }
Check 'WAZUH-LAB IPv4' (-not [string]::IsNullOrWhiteSpace($vmIp)) ([string]$vmIp)
if (-not [string]::IsNullOrWhiteSpace($vmIp)) {
    foreach ($port in @(22,443,1514,1515)) {
        Check "WAZUH-LAB TCP $port" (Test-Step13Tcp $vmIp $port 2500) "$vmIp`:$port"
    }

    if ((Test-Path -LiteralPath ([string]$settings.SshPrivateKey)) -and (Test-Path -LiteralPath ([string]$settings.SshKnownHosts))) {
        $probe = Invoke-Step13BatchSshProbe -Settings $settings -VmIp $vmIp -TimeoutMs 8000
        $detail = "$($settings.SshUser)@$vmIp using pinned WAZUH-LAB host key"
        if (-not $probe.Success -and -not [string]::IsNullOrWhiteSpace([string]$probe.StdErr)) {
            $detail += "; " + ([string]$probe.StdErr -replace "`r?`n", ' | ')
        }
        Check 'Batch SSH' ([bool]$probe.Success) $detail
    }
}

$iphlp = Get-Service iphlpsvc -ErrorAction SilentlyContinue
Check 'IP Helper' ($null -ne $iphlp -and $iphlp.Status -eq 'Running') 'iphlpsvc must be Running.'

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host "STEP 13 PREFLIGHT FAILED: $($failures.Count) check(s) need attention." -ForegroundColor Red
    exit 2
}
Write-Host ''
Write-Host 'STEP 13 PREFLIGHT PASS.' -ForegroundColor Green
Write-Host 'This check does not perform any Solr write.'
exit 0
