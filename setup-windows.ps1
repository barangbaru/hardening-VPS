# ==============================
# WINDOWS VPS HARDENING SCRIPT (ALL-IN-ONE)
# Windows Server 2016/2019/2022
#
# Includes:
# - Force run as Administrator (auto-elevate)
# - Create local user: clouduser (random password, no input) + allow RDP
# - Disable Guest account
# - Logon banner warning
# - RDP port -> 3889
# - Limit RDP max resolution -> 1280x1024 (server policy limit)
# - Firewall default inbound deny + allow RDP 3889 (optionally restrict by IP)
# - Disable SMBv1, NetBIOS, LM hash, anonymous enum
# - Disable NTLMv1 (prefer NTLMv2 only) + enable/require SMB signing (client+server)
# - RDP brute-force threshold via policy (Account Lockout Policy)
# - Enable auditing
# - Install IPBan (fail2ban-like for Windows)
# - Enable Microsoft Defender + ASR rules (Block)
# - Apply Explorer view (show hidden, show OS files, show extensions) to ALL user profiles
#
# Run:
#   powershell.exe -ExecutionPolicy Bypass -File .\windows-hardening.ps1
# ==============================

# ==============================
# FORCE RUN AS ADMIN (AUTO-ELEVATE)
# ==============================
function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "Not running as Administrator. Relaunching elevated..." -ForegroundColor Yellow
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs
    exit
}

$ErrorActionPreference = "Stop"

# ==============================
# CONFIG
# ==============================
$NewRdpPort      = 3889
$CloudUser       = "clouduser"
$PasswordLength  = 20

# RDP brute-force threshold via policy (Account Lockout Policy)
# Recommended ranges (adjust as needed):
$LockoutThreshold = 5      # failed attempts
$LockoutDuration  = 30     # minutes account locked
$LockoutWindow    = 30     # minutes window for counting attempts

# Optional: restrict RDP to trusted IPs only
# Example: $TrustedRdpIPs = @("203.0.113.10","198.51.100.25")
$TrustedRdpIPs   = @()

# Logon banner warning
$LogonBannerTitle = "WARNING: Authorized Access Only"
$LogonBannerText  = @"
This system is for authorized use only.
All activities may be monitored and recorded.
Unauthorized access is prohibited and may be prosecuted.
"@

Write-Host "Starting Windows VPS Hardening..." -ForegroundColor Cyan

# ==============================
# Helper: generate strong random password
# ==============================
function New-StrongRandomPassword {
    param([int]$Length = 20)

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

    for ($i = $pw.Count; $i -lt $Length; $i++) { $pw.Add((Get-RandChar $all)) }

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

# ==============================
# Create clouduser (robust: New-LocalUser -> fallback net user)
# ==============================
function LocalUser-Exists($name) {
    try {
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
            return [bool]$u
        }
    } catch {}

    cmd.exe /c "net user $name" >$null 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Create-CloudUser($name, $plainPassword) {
    $created = $false

    # Attempt 1: New-LocalUser
    try {
        if (Get-Command New-LocalUser -ErrorAction SilentlyContinue) {
            $sec = ConvertTo-SecureString $plainPassword -AsPlainText -Force
            New-LocalUser -Name $name `
                -Password $sec `
                -FullName "Cloud Support User" `
                -Description "Auto-created by hardening script" `
                -PasswordNeverExpires $true `
                -AccountNeverExpires $true | Out-Null
            $created = $true
        }
    } catch {
        Write-Host "New-LocalUser failed, fallback to net user..." -ForegroundColor Yellow
    }

    # Attempt 2: net user
    if (-not $created) {
        cmd.exe /c "net user $name $plainPassword /add /y" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "net user create failed (exit $LASTEXITCODE)" }

        # Best-effort: password never expires
        try { cmd.exe /c "wmic useraccount where name='$name' set PasswordExpires=false" | Out-Null } catch {}
        $created = $true
    }

    # Allow RDP login
    cmd.exe /c "net localgroup `"Remote Desktop Users`" $name /add" | Out-Null
    cmd.exe /c "net localgroup `"Users`" $name /add" | Out-Null

    return $created
}

# ==============================
# Explorer view for ALL user profiles (HKU loaded + load NTUSER.DAT per profile + Default User)
# ==============================
function Set-ExplorerViewForHiveRoot {
    param(
        [Parameter(Mandatory=$true)][string]$HiveRoot # e.g. "Registry::HKEY_USERS\S-1-5-21-...\Software..."
    )

    $adv = Join-Path $HiveRoot "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    New-Item -Path $adv -Force | Out-Null

    # Show hidden files/folders
    New-ItemProperty -Path $adv -Name "Hidden" -PropertyType DWord -Value 1 -Force | Out-Null
    # Show protected operating system files
    New-ItemProperty -Path $adv -Name "ShowSuperHidden" -PropertyType DWord -Value 1 -Force | Out-Null
    # Show file extensions
    New-ItemProperty -Path $adv -Name "HideFileExt" -PropertyType DWord -Value 0 -Force | Out-Null
}

function Apply-ExplorerViewToAllProfiles {
    Write-Host "Applying Explorer view to ALL user profiles (hidden + OS files + extensions)..." -ForegroundColor Cyan

    # 1) Already loaded user hives
    $loadedSids = @()
    try {
        $loadedSids = (Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
            Select-Object -ExpandProperty PSChildName)
    } catch {}

    foreach ($sid in $loadedSids) {
        try { Set-ExplorerViewForHiveRoot -HiveRoot ("Registry::HKEY_USERS\{0}" -f $sid) } catch {}
    }

    # 2) All local profiles from ProfileList (load NTUSER.DAT if not loaded)
    $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $profileKeys = Get-ChildItem $profileListPath -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' }

    foreach ($k in $profileKeys) {
        $sid = $k.PSChildName
        $profilePath = (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if (-not $profilePath) { continue }

        $ntuser = Join-Path $profilePath "NTUSER.DAT"
        if (-not (Test-Path $ntuser)) { continue }

        # If hive already loaded, skip load/unload
        $alreadyLoaded = Test-Path ("Registry::HKEY_USERS\{0}" -f $sid)
        if ($alreadyLoaded) {
            try { Set-ExplorerViewForHiveRoot -HiveRoot ("Registry::HKEY_USERS\{0}" -f $sid) } catch {}
            continue
        }

        # Load hive, set, unload
        try {
            reg.exe load ("HKU\{0}" -f $sid) $ntuser | Out-Null
            Set-ExplorerViewForHiveRoot -HiveRoot ("Registry::HKEY_USERS\{0}" -f $sid)
        } catch {
            Write-Host "Failed to load/set hive for SID $sid ($profilePath): $($_.Exception.Message)" -ForegroundColor Yellow
        } finally {
            try { reg.exe unload ("HKU\{0}" -f $sid) | Out-Null } catch {}
        }
    }

    # 3) Default user profile (for NEW users)
    $defaultNtUser = "C:\Users\Default\NTUSER.DAT"
    if (Test-Path $defaultNtUser) {
        $tempHive = "HKU\_DEFAULTUSER_HARDEN"
        try {
            reg.exe load $tempHive $defaultNtUser | Out-Null
            Set-ExplorerViewForHiveRoot -HiveRoot "Registry::HKEY_USERS\_DEFAULTUSER_HARDEN"
        } catch {
            Write-Host "Failed to set Default User hive: $($_.Exception.Message)" -ForegroundColor Yellow
        } finally {
            try { reg.exe unload $tempHive | Out-Null } catch {}
        }
    }
}

# ------------------------------
# 0) Ensure clouduser exists
# ------------------------------
$CloudPasswordPlain = $null
try {
    Write-Host "Ensuring local user '$CloudUser' exists..." -ForegroundColor Cyan
    if (-not (LocalUser-Exists $CloudUser)) {
        $CloudPasswordPlain = New-StrongRandomPassword -Length $PasswordLength
        $ok = Create-CloudUser -name $CloudUser -plainPassword $CloudPasswordPlain
        if ($ok) { Write-Host "User '$CloudUser' created + granted RDP access." -ForegroundColor Green }
    } else {
        Write-Host "User '$CloudUser' already exists. Skipping creation." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Cloud user creation FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

# ------------------------------
# 0b) Disable Guest account
# ------------------------------
Write-Host "Disabling Guest account..."
try {
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) { Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue }
    }
} catch {}
cmd.exe /c "net user Guest /active:no" | Out-Null

# ------------------------------
# 0c) Logon banner warning
# ------------------------------
Write-Host "Configuring logon banner warning..."
$logonReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
New-Item -Path $logonReg -Force | Out-Null
Set-ItemProperty -Path $logonReg -Name "legalnoticecaption" -Type String -Value $LogonBannerTitle
Set-ItemProperty -Path $logonReg -Name "legalnoticetext"    -Type String -Value $LogonBannerText

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
# 3b) Disable NTLMv1 (prefer NTLMv2 only) + SMB signing (client + server)
# ------------------------------
Write-Host "Disabling NTLMv1 (prefer NTLMv2 only) + enforcing SMB signing..."
# NTLM: send NTLMv2 only, refuse LM & NTLM (helps disable NTLMv1 usage)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
# Additional safe hardening for SMB guest auth
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f | Out-Null

# SMB signing - Server
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature  /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null
# SMB signing - Client (Workstation)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature  /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f | Out-Null

# ------------------------------
# 4) Secure RDP + enable RDP + NLA + clipboard off
# ------------------------------
Write-Host "Hardening RDP (enable + NLA + disable clipboard)..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableClip /t REG_DWORD /d 1 /f | Out-Null

# ------------------------------
# 4b) Limit RDP max resolution 1280x1024 (server policy)
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
# 6) Firewall default block inbound + allow RDP 3889
# ------------------------------
Write-Host "Configuring Windows Firewall (default inbound block)..."
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -Enabled True `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow

# Remove old Allow RDP rule
Get-NetFirewallRule -DisplayName "Allow RDP" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

if ($TrustedRdpIPs.Count -gt 0) {
    Write-Host "Allowing RDP only from trusted IPs: $($TrustedRdpIPs -join ', ')" -ForegroundColor Yellow
    New-NetFirewallRule -DisplayName "Allow RDP" `
        -Direction Inbound -Protocol TCP -LocalPort $NewRdpPort `
        -RemoteAddress ($TrustedRdpIPs -join ",") -Action Allow | Out-Null
} else {
    Write-Host "Allowing RDP from ANY IP (recommended: set TrustedRdpIPs)" -ForegroundColor Yellow
    New-NetFirewallRule -DisplayName "Allow RDP" `
        -Direction Inbound -Protocol TCP -LocalPort $NewRdpPort `
        -Action Allow | Out-Null
}

# ------------------------------
# 7) Disable unused services
# ------------------------------
Write-Host "Disabling unnecessary services..."
$services = @("Fax","XblGameSave","XboxNetApiSvc","WSearch","RemoteRegistry")
foreach ($svc in $services) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) { Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue }
}

# ------------------------------
# 8) RDP brute-force threshold via policy (Account Lockout Policy)
# ------------------------------
Write-Host "Setting Account Lockout Policy (RDP brute-force threshold)..."
cmd.exe /c "net accounts /lockoutthreshold:$LockoutThreshold" | Out-Null
cmd.exe /c "net accounts /lockoutduration:$LockoutDuration" | Out-Null
cmd.exe /c "net accounts /lockoutwindow:$LockoutWindow" | Out-Null

Write-Host "Setting password policy..."
cmd.exe /c "net accounts /minpwlen:12" | Out-Null
cmd.exe /c "net accounts /maxpwage:30" | Out-Null
cmd.exe /c "net accounts /uniquepw:5" | Out-Null

# ------------------------------
# 9) Enable audit logging
# ------------------------------
Write-Host "Enabling security auditing..."
auditpol /set /category:* /success:enable /failure:enable | Out-Null

# ------------------------------
# 10) Disable LM hash storage
# ------------------------------
Write-Host "Disabling LM Hash storage..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f | Out-Null

# ------------------------------
# 11) Apply Explorer view to ALL user profiles
# ------------------------------
Apply-ExplorerViewToAllProfiles

# Best-effort: refresh Explorer if exists (Server Core may not have it)
try { Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue } catch {}

# ------------------------------
# 12) Install IPBan (fail2ban-like)
# ------------------------------
Write-Host "Installing IPBan (fail2ban-like) ..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ipbanInstaller = Join-Path $env:TEMP "install_ipban_latest.ps1"
    $ipbanUrl = "https://raw.githubusercontent.com/DigitalRuby/IPBan/master/IPBanCore/Windows/Scripts/install_latest.ps1"
    Invoke-WebRequest -Uri $ipbanUrl -OutFile $ipbanInstaller -UseBasicParsing
    powershell.exe -ExecutionPolicy Bypass -File $ipbanInstaller -silent $true -autostart $true | Out-Null
    Write-Host "IPBan installed. Whitelist your admin IPs in IPBan config!" -ForegroundColor Yellow
} catch {
    Write-Host "IPBan install failed: $($_.Exception.Message)" -ForegroundColor Red
}

# ------------------------------
# 13) Enable Microsoft Defender + ASR rules (Block)
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
    Write-Host "Defender preference set failed (policy/SKU may restrict): $($_.Exception.Message)" -ForegroundColor Yellow
}

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
for ($i=0; $i -lt $AsrIds.Count; $i++) { $AsrActions += 1 } # Block

try {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $AsrIds -AttackSurfaceReductionRules_Actions $AsrActions
    Write-Host "ASR rules applied in BLOCK mode." -ForegroundColor Green
} catch {
    Write-Host "ASR apply failed (policy/SKU may restrict): $($_.Exception.Message)" -ForegroundColor Yellow
}

# ------------------------------
# DONE + Print credentials banner
# ------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host " HARDENING COMPLETED" -ForegroundColor Magenta
Write-Host (" RDP Port : {0}   (connect: mstsc -> IP:{0})" -f $NewRdpPort) -ForegroundColor Cyan
Write-Host " RDP Max  : 1280x1024 (server policy limit)" -ForegroundColor Cyan
Write-Host " Guest    : disabled" -ForegroundColor Cyan
Write-Host " Banner   : enabled" -ForegroundColor Cyan
Write-Host " NTLMv1   : disabled (prefers NTLMv2 only)" -ForegroundColor Cyan
Write-Host " SMB Sign : required (client+server)" -ForegroundColor Cyan
Write-Host " Explorer : applied to ALL profiles (hidden + OS files + extensions)" -ForegroundColor Cyan
Write-Host (" Lockout  : threshold={0}, duration={1}m, window={2}m" -f $LockoutThreshold,$LockoutDuration,$LockoutWindow) -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

if ($CloudPasswordPlain) {
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

Write-Host "Reboot recommended (especially for NTLM/SMB policy consistency)." -ForegroundColor Yellow
