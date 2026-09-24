param(
    [string[]]$CandidateIds = @(
        '1180000','1180001','1180002','1180003','1180004','1180005','1180006','1180007','1180008','1180009',
        '1180010','1180011','1180012','1180013','1180014','1180015','1180016','1180017','1180018','1180019',
        '1180020','1180021','1180022','1180023','1180097'
    ),
    [string]$ConfigPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf',
    [switch]$NoRestart
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell on FLOSVR01.'
}
if ($env:COMPUTERNAME -ne 'FLOSVR01') {
    throw "This controlled scope migration must run on FLOSVR01; current host is '$env:COMPUTERNAME'."
}
if ($CandidateIds.Count -ne 25) { throw 'Step 15 rollout requires exactly twenty-five explicit candidate IDs.' }
if (($CandidateIds | Select-Object -Unique).Count -ne $CandidateIds.Count) { throw 'CandidateIds contains duplicates.' }
foreach ($id in $CandidateIds) {
    if ($id -notmatch '^[0-9]{1,32}$') { throw "Invalid candidate ID: $id" }
}

$root = 'C:\Shares-DFS\FastTrack\Candidate\To 1189999'
foreach ($id in $CandidateIds) {
    $folder = Join-Path $root $id
    if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
        throw "Candidate folder is not accessible: $folder"
    }
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Wazuh config not found: $ConfigPath" }

$raw = [System.IO.File]::ReadAllText($ConfigPath)
# Preserve the stable manager hostname introduced in Step 13. Refuse to write a new scope if the
# agent has regressed to a DHCP address.
if ($raw -notmatch '(?i)<address>\s*MGMTNB08\s*</address>') {
    throw 'Wazuh server address is not MGMTNB08. Restore the Step 13 stable manager hostname before expanding scope.'
}
if ($raw -match '(?i)<address>\s*192\.168\.118\.[0-9]+\s*</address>') {
    throw 'Refusing Step 15 while Wazuh server address is pinned to a DHCP IPv4 address.'
}

$close = [regex]::Match($raw, '(?im)^(?<indent>[ \t]*)</syscheck>')
if (-not $close.Success) { throw 'Could not locate </syscheck> in ossec.conf.' }

# Remove every candidate-specific FIM directory entry under this exact controlled root.
# Use path-value normalization instead of one large regex. Earlier pilot entries can differ in
# whitespace/line formatting even when Select-String renders them identically, which allowed
# duplicate 1180001/1180003 entries to survive a regex-only cleanup.
$escapedRoot = [regex]::Escape($root)
$hadTrailingNewline = $raw.EndsWith("`r`n") -or $raw.EndsWith("`n")
$keptLines = New-Object System.Collections.Generic.List[string]
foreach ($line in ($raw -split "`r?`n")) {
    $drop = $false
    $m = [regex]::Match($line, '(?i)<directories\b[^>]*>(?<path>[^<]+)</directories>')
    if ($m.Success) {
        $pathValue = $m.Groups['path'].Value.Trim().TrimEnd('\','/')
        $prefix = $root + '\'
        if ($pathValue.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $candidateTail = $pathValue.Substring($prefix.Length)
            if ($candidateTail -match '^[0-9]{1,32}$') {
                $drop = $true
            }
        }
    }
    if (-not $drop) { [void]$keptLines.Add($line) }
}
$withoutManaged = $keptLines -join [Environment]::NewLine
if ($hadTrailingNewline -and -not $withoutManaged.EndsWith([Environment]::NewLine)) {
    $withoutManaged += [Environment]::NewLine
}
$close = [regex]::Match($withoutManaged, '(?im)^(?<indent>[ \t]*)</syscheck>')
if (-not $close.Success) { throw 'Could not relocate </syscheck> after candidate-line cleanup.' }
$indent = $close.Groups['indent'].Value + '  '
$lines = foreach ($id in $CandidateIds) {
    $path = "$root\$id"
    ('{0}<directories check_all="yes" realtime="yes" report_changes="no">{1}</directories>' -f $indent, $path)
}
$block = ($lines -join [Environment]::NewLine) + [Environment]::NewLine
$updated = $withoutManaged.Insert($close.Index, $block)

if ($updated -match ('(?i)<directories\b[^>]*>\s*' + $escapedRoot + '\s*</directories>')) {
    throw 'Refusing to write a root-wide candidate monitor. Step 15 remains explicit allowlist only.'
}
foreach ($id in $CandidateIds) {
    if ($updated -notmatch [regex]::Escape("$root\$id")) { throw "Generated config omitted candidate $id." }
}
$managedMatches = [regex]::Matches($updated, '(?im)^[ \t]*<directories\b[^>]*>\s*' + $escapedRoot + '\\[0-9]{1,32}[\\/]?\s*</directories>\s*$')
if ($managedMatches.Count -ne 25) {
    Write-Host "Managed candidate entries detected after cleanup:"
    $managedMatches | ForEach-Object { Write-Host ("  " + $_.Value.Trim()) }
    throw "Generated Wazuh config contains $($managedMatches.Count) managed candidate entries; expected exactly 25."
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = "$ConfigPath.step15-backup-$stamp"
Copy-Item -LiteralPath $ConfigPath -Destination $backup -Force
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ConfigPath, $updated, $utf8NoBom)

Write-Host "Step 15 Wazuh FIM allowlist written. Backup: $backup"
Write-Host "Candidate count: $($CandidateIds.Count)"
Write-Host "Candidates: $($CandidateIds -join ',')"
Select-String -Path $ConfigPath -Pattern ([regex]::Escape($root)) | ForEach-Object { Write-Host ('  ' + $_.Line.Trim()) }

if (-not $NoRestart) {
    Restart-Service WazuhSvc
    Start-Sleep -Seconds 8
    $svc = Get-Service WazuhSvc
    if ($svc.Status -ne 'Running') { throw 'WazuhSvc did not return to Running state.' }
    Write-Host 'WazuhSvc restarted and is Running.'
    Write-Host 'Check ossec.log for one realtime monitor line per allowlisted candidate.'
}
