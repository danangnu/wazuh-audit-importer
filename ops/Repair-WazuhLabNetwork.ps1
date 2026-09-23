param(
    [string]$SettingsPath,
    [switch]$PassThru
)

. "$PSScriptRoot\Step13.Common.ps1"
Assert-Step13Administrator
$settings = Import-Step13Settings $SettingsPath
$vmIp = Get-Step13VmIpv4 $settings
if ([string]::IsNullOrWhiteSpace($vmIp)) {
    throw "VM '$($settings.VmName)' is not running or no IPv4 address is visible through Hyper-V integration services."
}

$requiredPorts = @(
    @{ Listen = 8443; Connect = 443 },
    @{ Listen = 1514; Connect = 1514 },
    @{ Listen = 1515; Connect = 1515 }
)

foreach ($entry in $requiredPorts) {
    if (-not (Test-Step13Tcp $vmIp $entry.Connect 2500)) {
        throw "WAZUH-LAB $vmIp is not accepting TCP $($entry.Connect). Do not rewrite forwarding until the target service is reachable."
    }
}

$iphlp = Get-Service iphlpsvc -ErrorAction Stop
if ($iphlp.Status -ne 'Running') { Start-Service iphlpsvc }

# Remove only mappings on the three project-owned listen ports whose connect port matches this lab.
$raw = & netsh interface portproxy show v4tov4 2>$null
foreach ($line in $raw) {
    if ($line -match '^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*$') {
        $listenAddress = $Matches[1]
        $listenPort = [int]$Matches[2]
        $connectPort = [int]$Matches[4]
        $expected = $requiredPorts | Where-Object { $_.Listen -eq $listenPort -and $_.Connect -eq $connectPort }
        if ($null -ne $expected) {
            & netsh interface portproxy delete v4tov4 listenaddress=$listenAddress listenport=$listenPort protocol=tcp | Out-Null
        }
    }
}

foreach ($entry in $requiredPorts) {
    & netsh interface portproxy add v4tov4 `
        listenaddress=$([string]$settings.ForwardListenAddress) `
        listenport=$($entry.Listen) `
        connectaddress=$vmIp `
        connectport=$($entry.Connect) `
        protocol=tcp | Out-Null
}

$ruleName = 'WazuhLab-Step13-Forwarding-FLOSVR01'
Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
New-NetFirewallRule `
    -Name $ruleName `
    -DisplayName 'Wazuh lab Step 13 forwarding - FLOSVR01 only' `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 8443,1514,1515 `
    -RemoteAddress ([string]$settings.ForwardRemoteAddress) `
    -Profile Any | Out-Null

# The old pilot rule may be tied to a DHCP address; disable it after the broad-listener/restricted-remote rule exists.
Disable-NetFirewallRule -Name 'WazuhLab-Forwarding-FLOSVR01' -ErrorAction SilentlyContinue

Restart-Service iphlpsvc
Start-Sleep -Milliseconds 750

$result = [ordered]@{
    vm_name = [string]$settings.VmName
    vm_ip = $vmIp
    listen_address = [string]$settings.ForwardListenAddress
    remote_allowed = [string]$settings.ForwardRemoteAddress
    ports = @(8443,1514,1515)
    repaired_utc = [DateTime]::UtcNow.ToString('o')
}

Write-Host "Step 13 network forwarding repaired."
Write-Host "  WAZUH-LAB : $vmIp"
Write-Host "  Listen    : $($settings.ForwardListenAddress):8443/1514/1515"
Write-Host "  FLOSVR01  : $($settings.ForwardRemoteAddress) only"
Write-Host "  Agent target should be stable hostname MGMTNB08 after the FLOSVR01 one-time migration."

if ($PassThru) { [pscustomobject]$result }
