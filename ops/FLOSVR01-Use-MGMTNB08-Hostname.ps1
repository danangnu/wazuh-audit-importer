param(
    [string]$ManagerHost = 'MGMTNB08',
    [string]$ConfigPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script on FLOSVR01 in an elevated PowerShell window.'
}
if ($env:COMPUTERNAME -ne 'FLOSVR01') {
    throw "This script is intended for FLOSVR01. Current host is '$env:COMPUTERNAME'."
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Wazuh agent config not found: $ConfigPath"
}

$resolved = Resolve-DnsName $ManagerHost -Type A -ErrorAction Stop | Select-Object -First 1
Write-Host "Resolved $ManagerHost -> $($resolved.IPAddress)"
$tcp = Test-NetConnection $ManagerHost -Port 1514 -WarningAction SilentlyContinue
if (-not $tcp.TcpTestSucceeded) {
    throw "${ManagerHost}:1514 is not reachable from FLOSVR01. Do not change ossec.conf until Step 13 portproxy/firewall is working."
}

$backup = "$ConfigPath.step13-$((Get-Date).ToString('yyyyMMdd-HHmmss')).bak"
Copy-Item -LiteralPath $ConfigPath -Destination $backup -Force

[xml]$xml = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
$serverNodes = @($xml.SelectNodes('/ossec_config/client/server/address'))
if ($serverNodes.Count -eq 0) { throw 'No /ossec_config/client/server/address node found. Backup was created; no edit was made.' }
foreach ($node in $serverNodes) { $node.InnerText = $ManagerHost }
$enrollmentNodes = @($xml.SelectNodes('/ossec_config/client/enrollment/manager_address'))
foreach ($node in $enrollmentNodes) { $node.InnerText = $ManagerHost }

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$writerSettings = New-Object System.Xml.XmlWriterSettings
$writerSettings.Indent = $true
$writerSettings.Encoding = $utf8NoBom
$writer = [System.Xml.XmlWriter]::Create($ConfigPath, $writerSettings)
try { $xml.Save($writer) } finally { $writer.Dispose() }

Restart-Service WazuhSvc
Start-Sleep -Seconds 5
$log = 'C:\Program Files (x86)\ossec-agent\ossec.log'
Write-Host "Backup: $backup"
Write-Host "Wazuh agent manager changed to stable hostname: $ManagerHost"
if (Test-Path -LiteralPath $log) {
    Get-Content -LiteralPath $log -Tail 20
}
