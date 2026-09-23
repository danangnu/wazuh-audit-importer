param(
    [string]$SettingsPath,
    [switch]$Force
)

. "$PSScriptRoot\Step13.Common.ps1"
$settings = Import-Step13Settings $SettingsPath
$dir = [string]$settings.SecretDirectory
New-Item -ItemType Directory -Path $dir -Force | Out-Null

function Save-Secret {
    param([string]$Label,[string]$Path)
    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        $answer = Read-Host "$Label secret already exists. Replace it? Type YES to replace"
        if ($answer -ne 'YES') {
            Write-Host "Keeping existing $Label secret."
            return
        }
    }
    $secure = Read-Host "$Label password" -AsSecureString
    $cipher = ConvertFrom-SecureString $secure
    Set-Content -LiteralPath $Path -Value $cipher -Encoding ASCII
    Write-Host "Stored $Label secret with Windows DPAPI for user $([Security.Principal.WindowsIdentity]::GetCurrent().Name)."
}

Save-Secret 'MariaDB' (Get-Step13SecretFile $settings 'db')
Save-Secret 'Wazuh Indexer' (Get-Step13SecretFile $settings 'indexer')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $dir /inheritance:r | Out-Null
& icacls.exe $dir /grant:r "${identity}:(OI)(CI)(F)" | Out-Null

Write-Host ''
Write-Host 'Step 13 secrets initialized.'
Write-Host "Directory: $dir"
Write-Host 'No plaintext password is written to the repository or task definition.'
Write-Host 'DPAPI files can only be decrypted by this Windows user on this machine.'
