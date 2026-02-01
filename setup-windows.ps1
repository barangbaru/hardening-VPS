# ==============================
# WINDOWS VPS HARDENING SCRIPT
# + RDP port -> 3889
# + IPBan (fail2ban-like)
# + Microsoft Defender + ASR rules
# + Create user clouduser with random password, allow RDP
# + Limit RDP max resolution 1280x1024
# ==============================
# Tested: Windows Server 2016/2019/2022
# Run as Administrator
# ==============================

$ErrorActionPreference = "Stop"

# --- CONFIG ---
$NewRdpPort = 3889
$CloudUser  = "clouduser"
$PasswordLength = 20

# (Optional) isi IP admin yang boleh masuk RDP supaya firewall lebih ketat
# Contoh: $TrustedRdpIPs = @("203.0.113.10","198.51.100.25")
$TrustedRdpIPs = @()

# ------------------------------
# Helper: generate strong random password
# ------------------------------
function New-StrongRandomPassword {
    param([int]$Length = 20)

    # Ensure complexity: at least 1 upper, 1 lower, 1 digit, 1 symbol
    $upper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $lower  = "abcdefghijkmnpqrstuvwxyz"
    $digits = "23456789"
    $sym    = "!@#%+=_-?*"
    $all    = ($upper + $lower + $digits + $sym).ToCharArray()

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    function Get-RandChar([char[]]$set) {
        $b = New-Object byte[] 4
        $rng.GetBytes($b)
        $idx = [BitConverter]::ToUInt32($b,0) % $set.Length
        return $set[$idx]
    }

    $pw = New-Object System.Collections.Generic.List[char]
    $pw.Add((Get-RandChar $upper.ToCharArray()))
    $pw.Add((Get-RandChar $lower.ToCharArray()))
    $pw.Add((Get-RandChar $digits.ToCharArray()))
    $pw.Add((Get-RandChar $sym.ToCharArray()))

    for ($i = $pw.Count; $i -lt $Length; $i++) {
        $pw.Add((Get-RandChar $all))
    }

    # Shuffle
    for ($i = $pw.Count - 1; $i -gt 0; $i--) {
        $b = New-Object byte[] 4
        $rng.GetBytes($b)
        $j = [BitConverter]::ToUInt32($b,0) % ($i + 1)
        $tmp = $pw[$i]; $pw[$i] = $pw[$j]; $pw[$j] = $tmp
    }

    $rng.Dispose()
    return -join $pw
}

Write-Host "Starting Windows VPS Hardening..." -ForegroundColor Cyan

# ------------------------------
# 0) Create clouduser with random password + allow RDP
# ------------------------------
$CloudPasswordPlain = $null
try {
    $existing = Get-LocalUser -Name $CloudUser -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Host "Creating local user '$CloudUser' with random password..."
        $CloudPasswordPlain = New-StrongRandomPassword -Length $PasswordLength
        $sec = ConvertTo-SecureString $CloudPasswordPlain -AsPlainText -Force

        New-LocalUser -Name $CloudUser `
            -Password $sec `
            -FullName "Cloud Support User" `
            -Description "Auto-created by hardening script" `
            -PasswordNeverExpires $true `
            -AccountNeverExpires $true | Out-Null

        # Allow RDP login by group membership
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $CloudUser -ErrorAction SilentlyContinue

        Write-Host "User '$CloudUser' created and added to 'Remote Desktop Users'." -ForegroundColor Green
    } else {
        Write-Host "User '$CloudUser' already exists. Skipping creation." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Cloud user creation failed: $($_.Exception.Message)" -ForegroundColor Red
}

# ------------------------------
# 1) Disable SMBv1
# ------------------------------
Write-Host "Disabling SMBv1..."
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue

# ------------------------------
# 2) Disable NetBIOS
# ------------------------------
Write-Host "Disabling NetBIOS..."
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled} | ForEach-Object {
    $_.SetTcpipNetbios(2) | Out-Null
}

# ------------------------------
# 3) Restrict Anonymous Enumeration
# ------------------------------
Write-Host "Hardening anonymous access..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f | Out-Null

# ------------------------------
# 7) Disable Unused Services
# ------------------------------
Write-Host "Disabling unnecessary services..."
$services = @("Fax","XblGameSave","XboxNetApiSvc","WSearch","RemoteRegistry")
foreach ($svc in $services) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue }
}

# ------------------------------
# 8) Account Lockout + Password Policy
# ------------------------------
Write-Host "Setting account lockout policy..."
net accounts /lockoutthreshold:5 | Out-Null
net accounts /lockoutduration:30 | Out-Null
net accounts /lockoutwindow:30 | Out-Null

Write-Host "Setting password policy..."
net accounts /minpwlen:12 | Out-Null
net accounts /maxpwage:30 | Out-Null
net accounts /uniquepw:5 | Out-Null

# ------------------------------
# 9) Enable Audit Logging
# ------------------------------
Write-Host "Enabling security auditing..."
auditpol /set /category:* /success:enable /failure:enable | Out-Null

# ------------------------------
# 10) Disable LM Hash storage
# ------------------------------
Write-Host "Disabling LM Hash storage..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f | Out-Null

# ------------------------------
# 11) Install IPBan (Fail2Ban for Windows)
# ------------------------------
Write-Host "Installing IPBan (fail2ban-like) ..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ipbanInstaller = Join-Path $env:TEMP "install_ipban_latest.ps1"
    $ipbanUrl = "https://raw.githubusercontent.com/DigitalRuby/IPBan/master/IPBanCore/Windows/Scripts/install_latest.ps1"

    Invoke-WebRequest -Uri $ipbanUrl -OutFile $ipbanInstaller -UseBasicParsing

    # silent install + autostart service
    powershell.exe -ExecutionPolicy Bypass -File $ipbanInstaller -silent $true -autostart $true | Out-Null

    Write-Host "IPBan installed. IMPORTANT: whitelist your admin IPs in IPBan config!" -ForegroundColor Yellow
    Write-Host "Config usually: C:\Program Files\IPBan\ipban.config (or ipban.override.config)" -ForegroundColor Yellow
} catch {
    Write-Host "IPBan install failed: $($_.Exception.Message)" -ForegroundColor Red
}

# ------------------------------
# 12) Enable Microsoft Defender + Cloud protection + ASR Rules (Block)
# ------------------------------
Write-Host "Enabling Microsoft Defender settings + ASR rules..."

try {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -DisableScriptScanning $false

    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent 1
    Set-MpPreference -DisableBlockAtFirstSeen $false
    Set-MpPreference -CloudBlockLevel High
} catch {
    Write-Host "Defender preference set failed (some SKUs/policies may restrict this): $($_.Exception.Message)" -ForegroundColor Yellow
}

# ASR Rules (Block=1, Audit=2, Warn=6)
$AsrIds = @(
    "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
    "01443614-cd74-433a-b99e-2ecdc07bfc25",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
    "d3e037e1-3eb8-44c8-a917-57927947596d",
    "3b576869-a4ec-4529-8536-b80a7769e899",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "26190899-1602-49e8-8b27-eb1d0a1ce869",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b",
    "d1e49aac-8f56-4280-b9ba-993a6d77406c",
    "33ddedf1-c6e0-47cb-833e-de6133960387",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb",
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b",
    "c1db55ab-c21a-4637-bb3f-a12568109d35"
)
$AsrActions = @()
for ($i=0; $i -lt $AsrIds.Count; $i++) { $AsrActions += 1 } # all Block

try {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $AsrIds -AttackSurfaceReductionRules_Actions $AsrActions
    Write-Host "ASR rules applied in BLOCK mode." -ForegroundColor Green
} catch {
    Write-Host "ASR apply failed (some editions require Defender components/policies): $($_.Exception.Message)" -ForegroundColor Yellow
}

# ------------------------------
# 4) Secure RDP (enable RDP + NLA + clipboard off)
# ------------------------------
Write-Host "Hardening RDP (enable + NLA + disable clipboard)..."
# Ensure RDP enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f | Out-Null

# Enable NLA
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
/v UserAuthentication /t REG_DWORD /d 1 /f | Out-Null

# Disable RDP clipboard
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" `
/v fDisableClip /t REG_DWORD /d 1 /f | Out-Null

# ------------------------------
# 4b) Limit RDP max resolution to 1280x1024
# (This limits sessions; client may choose smaller, but not larger.)
# ------------------------------
Write-Host "Setting RDP max resolution limit to 1280x1024..."
$tsPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
New-Item -Path $tsPol -Force | Out-Null
New-ItemProperty -Path $tsPol -Name "MaxXResolution" -PropertyType DWord -Value 1280 -Force | Out-Null
New-ItemProperty -Path $tsPol -Name "MaxYResolution" -PropertyType DWord -Value 1024 -Force | Out-Null

# ------------------------------
# 5) Change RDP Port -> 3889 + restart TermService
# ------------------------------
Write-Host "Changing RDP port to $NewRdpPort..."
$rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
Set-ItemProperty -Path $rdpRegPath -Name "PortNumber" -Value $NewRdpPort -Type DWord

Write-Host "Restarting TermService..."
Restart-Service -Name TermService -Force

# ------------------------------
# 6) Windows Firewall - Default Deny + Allow RDP 3889
# ------------------------------
Write-Host "Configuring Windows Firewall (default inbound block)..."
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -Enabled True `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow

# Remove old "Allow RDP" rule if exists (avoid leaving 3389 open)
Get-NetFirewallRule -DisplayName "Allow RDP" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# Create allow rule for new RDP port
if ($TrustedRdpIPs.Count -gt 0) {
    Write-Host "Allowing RDP only from trusted IPs: $($TrustedRdpIPs -join ', ')"
    New-NetFirewallRule -DisplayName "Allow RDP" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort $NewRdpPort `
        -RemoteAddress ($TrustedRdpIPs -join ",") `
        -Action Allow | Out-Null
} else {
    Write-Host "Allowing RDP from ANY IP (recommended: set TrustedRdpIPs)"
    New-NetFirewallRule -DisplayName "Allow RDP" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort $NewRdpPort `
        -Action Allow | Out-Null
}

# ------------------------------
# DONE + print credentials
# ------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host " HARDENING COMPLETED" -ForegroundColor Magenta
Write-Host " RDP Port : $NewRdpPort   (connect: mstsc -> IP:$NewRdpPort)" -ForegroundColor Cyan
Write-Host " RDP Max  : 1280x1024 (server policy limit)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

if ($CloudPasswordPlain) {
    # "Bold/bigger" isn't truly possible in standard console output,
    # so we use a big banner + bright color to make it stand out.
Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host " HARDENING COMPLETED" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta

if ($CloudPasswordPlain) {
    Write-Host ""
    Write-Host "██████╗ ██╗      ██████╗ ██╗   ██╗██████╗" -ForegroundColor Yellow
    Write-Host "██╔══██╗██║     ██╔═══██╗██║   ██║██╔══██╗" -ForegroundColor Yellow
    Write-Host "██║  ██║██║     ██║   ██║██║   ██║██║  ██║" -ForegroundColor Yellow
    Write-Host "██║  ██║██║     ██║   ██║██║   ██║██║  ██║" -ForegroundColor Yellow
    Write-Host "██████╔╝███████╗╚██████╔╝╚██████╔╝██████╔╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host ("USERNAME : {0}" -f $CloudUser) -ForegroundColor Green
    Write-Host ("PASSWORD : {0}" -f $CloudPasswordPlain) -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "Clouduser password not printed (user already existed or creation failed)." -ForegroundColor Yellow
}

Write-Host "Reboot recommended." -ForegroundColor Yellow
