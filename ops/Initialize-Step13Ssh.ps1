param(
    [string]$SettingsPath,
    [switch]$SkipPublicKeyInstall
)

. "$PSScriptRoot\Step13.Common.ps1"
$settings = Import-Step13Settings $SettingsPath
$vmIp = Get-Step13VmIpv4 $settings
if ([string]::IsNullOrWhiteSpace($vmIp)) { throw "Start VM '$($settings.VmName)' first." }

$ssh = Get-Command ssh.exe -ErrorAction Stop
$sshKeyGen = Get-Command ssh-keygen.exe -ErrorAction Stop
$sshKeyScan = Get-Command ssh-keyscan.exe -ErrorAction Stop
$keyPath = [string]$settings.SshPrivateKey
$knownHosts = [string]$settings.SshKnownHosts
New-Item -ItemType Directory -Path (Split-Path -Parent $keyPath) -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path -Parent $knownHosts) -Force | Out-Null

if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
    # Windows PowerShell 5.1 drops a native-command empty-string argument.
    # Pass a quoted empty string so ssh-keygen receives -N with an empty passphrase.
    & $sshKeyGen.Source -q -t ed25519 -f $keyPath -N '""' -C 'WazuhAuditImporter-Step13-MGMTNB08'
    if ($LASTEXITCODE -ne 0) { throw 'ssh-keygen failed.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $keyPath /inheritance:r | Out-Null
    & icacls.exe $keyPath /grant:r "${identity}:(F)" | Out-Null
    Write-Host "Created dedicated Step 13 SSH key: $keyPath"
} else {
    Write-Host "Using existing dedicated SSH key: $keyPath"
}

$pinnedLine = $null
if (Test-Path -LiteralPath $knownHosts -PathType Leaf) {
    $pinnedLine = Get-Content -LiteralPath $knownHosts -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '^WAZUH-LAB\s+ssh-ed25519\s+\S+' } |
        Select-Object -First 1
}

if ($pinnedLine) {
    # The operator already verified and pinned this host key on an earlier run.
    # Reuse it under HostKeyAlias=WAZUH-LAB rather than requiring ssh-keyscan
    # (which may not support Ubuntu's advertised hybrid KEX on older Windows builds).
    $tempPinned = [System.IO.Path]::GetTempFileName()
    try {
        Set-Content -LiteralPath $tempPinned -Value $pinnedLine -Encoding ASCII
        $fpOutput = & $sshKeyGen.Source -lf $tempPinned -E sha256
        if ($LASTEXITCODE -ne 0) { throw 'Could not calculate pinned SSH host-key fingerprint.' }
        $pinnedFingerprint = (($fpOutput -split '\s+') | Where-Object { $_ -like 'SHA256:*' } | Select-Object -First 1)
        Write-Host "Using existing pinned WAZUH-LAB host key: $pinnedFingerprint"
    }
    finally {
        Remove-Item -LiteralPath $tempPinned -Force -ErrorAction SilentlyContinue
    }
}
else {
    $tempHost = [System.IO.Path]::GetTempFileName()
    try {
        $hostLine = $null
        $scanError = ''

        # First try ssh-keyscan. Some Windows OpenSSH builds cannot negotiate
        # Ubuntu 24.04's advertised hybrid sntrup KEX and fail before returning
        # a host key. In that case use an operator-verified console copy.
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $sshKeyScan.Source
        $psi.Arguments = "-T 5 -t ed25519 $vmIp"
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        $scanText = $proc.StandardOutput.ReadToEnd()
        $scanError = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()

        $scan = @($scanText -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($proc.ExitCode -eq 0 -and $scan.Count -gt 0) {
            $hostLine = @($scan | Where-Object { $_ -match 'ssh-ed25519' } | Select-Object -First 1)
        }

        if (-not $hostLine) {
            Write-Host ''
            Write-Warning 'ssh-keyscan could not negotiate a host key with this Windows OpenSSH build.'
            if (-not [string]::IsNullOrWhiteSpace($scanError)) {
                Write-Host (($scanError -replace "`r?`n", ' ').Trim())
            }
            Write-Host 'Use the WAZUH-LAB console for a verified manual fallback.'
            Write-Host 'On Ubuntu run:'
            Write-Host '  cat /etc/ssh/ssh_host_ed25519_key.pub'
            Write-Host '  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256'
            Write-Host ''
            $manualKey = Read-Host 'Paste the FULL ssh-ed25519 public-key line from the Ubuntu console'
            $manualParts = @($manualKey.Trim() -split '\s+')
            if ($manualParts.Count -lt 2 -or $manualParts[0] -ne 'ssh-ed25519' -or [string]::IsNullOrWhiteSpace($manualParts[1])) {
                throw 'The pasted host key is not a valid ssh-ed25519 public-key line.'
            }
            $hostLine = "$vmIp ssh-ed25519 $($manualParts[1])"
        }

        $parts = @($hostLine -split '\s+')
        $keyTypeIndex = [Array]::IndexOf($parts, 'ssh-ed25519')
        if ($keyTypeIndex -lt 0 -or ($keyTypeIndex + 1) -ge $parts.Count) {
            throw 'No valid Ed25519 SSH host key was obtained.'
        }
        $aliasLine = "WAZUH-LAB ssh-ed25519 $($parts[$keyTypeIndex + 1])"
        Set-Content -LiteralPath $tempHost -Value $aliasLine -Encoding ASCII
        $fpOutput = & $sshKeyGen.Source -lf $tempHost -E sha256
        if ($LASTEXITCODE -ne 0) { throw 'Could not calculate SSH host-key fingerprint.' }
        $scannedFingerprint = (($fpOutput -split '\s+') | Where-Object { $_ -like 'SHA256:*' } | Select-Object -First 1)
        if ([string]::IsNullOrWhiteSpace($scannedFingerprint)) { throw 'Could not parse SSH host-key fingerprint.' }

        Write-Host ''
        Write-Host "Candidate WAZUH-LAB host fingerprint: $scannedFingerprint"
        Write-Host 'On the Ubuntu WAZUH-LAB console run:'
        Write-Host '  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256'
        $confirmed = Read-Host 'Paste the SHA256:... fingerprint shown by WAZUH-LAB'
        if ($confirmed.Trim() -ne $scannedFingerprint) {
            throw 'Host-key fingerprint mismatch. Nothing was trusted. Investigate before continuing.'
        }
        Set-Content -LiteralPath $knownHosts -Value $aliasLine -Encoding ASCII
        Write-Host "Pinned WAZUH-LAB host key under stable alias in: $knownHosts"
    }
    finally {
        Remove-Item -LiteralPath $tempHost -Force -ErrorAction SilentlyContinue
    }
}

if (-not $SkipPublicKeyInstall) {
    Write-Host ''
    Write-Host "Installing the public key for $($settings.SshUser)@$vmIp."
    Write-Host 'The existing Ubuntu account password may be requested once.'

    # Do not pipe key data through ssh stdin and do not place the decoded key
    # in a shell variable. Windows ssh.exe can strip nested quoting from the
    # remote command, which would split an SSH key at its spaces. Decode the
    # Base64 into a temporary remote file and use grep -f/cat instead.
    $publicKey = (Get-Content -LiteralPath "$keyPath.pub" -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($publicKey)) { throw 'Step 13 public key file is empty.' }
    $publicKeyB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($publicKey))
    $remoteInstall = "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; echo $publicKeyB64 | base64 -d > ~/.ssh/.wazuh-step13.pub; echo >> ~/.ssh/.wazuh-step13.pub; grep -qxF -f ~/.ssh/.wazuh-step13.pub ~/.ssh/authorized_keys || cat ~/.ssh/.wazuh-step13.pub >> ~/.ssh/authorized_keys; rm -f ~/.ssh/.wazuh-step13.pub; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys"

    & $ssh.Source `
        -o 'ConnectTimeout=10' `
        -o "UserKnownHostsFile=$knownHosts" `
        -o 'HostKeyAlias=WAZUH-LAB' `
        -o 'StrictHostKeyChecking=yes' `
        "$($settings.SshUser)@$vmIp" `
        $remoteInstall
    if ($LASTEXITCODE -ne 0) { throw 'Public-key installation failed.' }
}

& $ssh.Source `
    -o 'BatchMode=yes' `
    -o 'ConnectTimeout=5' `
    -o "UserKnownHostsFile=$knownHosts" `
    -o 'HostKeyAlias=WAZUH-LAB' `
    -o 'StrictHostKeyChecking=yes' `
    -i $keyPath `
    "$($settings.SshUser)@$vmIp" `
    'true'
if ($LASTEXITCODE -ne 0) {
    throw 'Batch-mode SSH test failed. Step 13 cannot run unattended until key authentication works.'
}

Write-Host ''
Write-Host 'Step 13 SSH initialization PASS.'
Write-Host "Batch-mode SSH to WAZUH-LAB works at current VM IP $vmIp using HostKeyAlias=WAZUH-LAB."
