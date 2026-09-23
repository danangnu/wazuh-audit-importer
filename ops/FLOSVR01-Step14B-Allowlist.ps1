param(
    [string[]]$CandidateIds = @('1180000','1180001','1180002','1180003','1180097'),
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
    throw "This one-time scope migration must run on FLOSVR01; current host is '$env:COMPUTERNAME'."
}
if ($CandidateIds.Count -ne 5) { throw 'Step 14B pilot requires exactly five explicit candidate IDs.' }
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
$close = [regex]::Match($raw, '(?im)^(?<indent>[ \t]*)</syscheck>')
if (-not $close.Success) { throw 'Could not locate </syscheck> in ossec.conf.' }

# Remove only candidate-specific FIM directory lines under this exact controlled root.
$escapedRoot = [regex]::Escape($root)
$managedPattern = '(?im)^[ \t]*<directories\b[^>]*>\s*' + $escapedRoot + '\\[0-9]{1,32}\s*</directories>\s*\r?\n?'
$withoutManaged = [regex]::Replace($raw, $managedPattern, '')
$close = [regex]::Match($withoutManaged, '(?im)^(?<indent>[ \t]*)</syscheck>')
if (-not $close.Success) { throw 'Could not relocate </syscheck> after candidate-line cleanup.' }
$indent = $close.Groups['indent'].Value + '  '
$lines = foreach ($id in $CandidateIds) {
    $path = "$root\$id"
    ('{0}<directories check_all="yes" realtime="yes" report_changes="no">{1}</directories>' -f $indent, $path)
}
$block = ($lines -join [Environment]::NewLine) + [Environment]::NewLine
$updated = $withoutManaged.Insert($close.Index, $block)

# Fail closed if the update accidentally created a root-wide monitor or omitted an allowlisted path.
if ($updated -match ('(?i)<directories\b[^>]*>\s*' + $escapedRoot + '\s*</directories>')) {
    throw 'Refusing to write a root-wide candidate monitor. Step 14B must remain explicit allowlist only.'
}
foreach ($id in $CandidateIds) {
    if ($updated -notmatch [regex]::Escape("$root\$id")) { throw "Generated config omitted candidate $id." }
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = "$ConfigPath.step14b-backup-$stamp"
Copy-Item -LiteralPath $ConfigPath -Destination $backup -Force
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ConfigPath, $updated, $utf8NoBom)

Write-Host "Step 14B Wazuh FIM allowlist written. Backup: $backup"
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
