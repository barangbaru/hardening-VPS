# ------------------------------
# RDP ULTRA PERFORMANCE TUNING
# VPS PROFILE: AUTOMATION / BOT
# ------------------------------
Write-Host "Applying RDP Ultra Performance Optimization..." -ForegroundColor Cyan

$rdpPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
New-Item -Path $rdpPol -Force | Out-Null

# ==============================
# RDP NETWORK OPTIMIZATION
# ==============================

# Enable compression
Set-ItemProperty -Path $rdpPol -Name "UseRdpCompression" -Type DWord -Value 1

# Force low-latency mode
Set-ItemProperty -Path $rdpPol -Name "NetworkDetect" -Type DWord -Value 0
Set-ItemProperty -Path $rdpPol -Name "MinSendInterval" -Type DWord -Value 5

# ==============================
# DISABLE HEAVY UI (RDP POLICY)
# ==============================

Set-ItemProperty -Path $rdpPol -Name "fDisableWallpaper"      -Type DWord -Value 1
Set-ItemProperty -Path $rdpPol -Name "fDisableFullWindowDrag" -Type DWord -Value 1
Set-ItemProperty -Path $rdpPol -Name "fDisableMenuAnims"      -Type DWord -Value 1
Set-ItemProperty -Path $rdpPol -Name "fDisableThemes"         -Type DWord -Value 1

# Disable font smoothing via RDP
Set-ItemProperty -Path $rdpPol -Name "fAllowFontSmoothing"    -Type DWord -Value 0

# ==============================
# WINDOWS UI HARD DISABLE (USER LEVEL)
# ==============================

$desktopReg = "HKCU:\Control Panel\Desktop"
New-Item -Path $desktopReg -Force | Out-Null

# Disable animations & UI effects
Set-ItemProperty -Path $desktopReg -Name "DragFullWindows" -Value "0"
Set-ItemProperty -Path $desktopReg -Name "MenuShowDelay" -Value "0"

# Disable font smoothing
Set-ItemProperty -Path $desktopReg -Name "FontSmoothing" -Value "0"
Set-ItemProperty -Path $desktopReg -Name "FontSmoothingType" -Type DWord -Value 0

# ==============================
# DISABLE TRANSPARENCY
# ==============================
$personalize = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
New-Item -Path $personalize -Force | Out-Null
Set-ItemProperty -Path $personalize -Name "EnableTransparency" -Type DWord -Value 0

# ==============================
# DISABLE SHADOW EFFECTS
# ==============================
$visualFX = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
New-Item -Path $visualFX -Force | Out-Null
Set-ItemProperty -Path $visualFX -Name "VisualFXSetting" -Type DWord -Value 2  # Best performance

# ==============================
# EXTRA: Disable system animations globally
# ==============================
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f | Out-Null

Write-Host "RDP Ultra Performance Mode ENABLED (Low latency, no UI overhead)" -ForegroundColor Green


# ------------------------------
# VMWARE ESXI WINDOWS SERVER PERFORMANCE TUNING
# VPS/VM PROFILE: LIGHTWEIGHT AUTOMATION / BOT
# ------------------------------
Write-Host "Applying VMware ESXi Windows Server Lightweight Optimization..." -ForegroundColor Cyan

# ==============================
# 1. Disable unnecessary services for VM / automation server
# ==============================
$vmPerfServices = @(
    "SysMain",              # Superfetch
    "WSearch",              # Windows Search Indexing
    "DiagTrack",            # Connected User Experiences / Telemetry
    "dmwappushservice",     # WAP Push Message Routing
    "MapsBroker",           # Downloaded Maps Manager
    "lfsvc",                # Geolocation Service
    "RetailDemo",           # Retail Demo Service
    "XblGameSave",
    "XboxNetApiSvc",
    "WerSvc",               # Windows Error Reporting
    "PcaSvc"                # Program Compatibility Assistant
)

foreach ($svc in $vmPerfServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Disabling service: $svc"
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

# ==============================
# 2. Disable scheduled tasks that waste resource in VM
# ==============================
Write-Host "Disabling unnecessary scheduled tasks..."

$tasksToDisable = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Application Experience\StartupAppTask",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Maps\MapsToastTask",
    "\Microsoft\Windows\Maps\MapsUpdateTask",
    "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
    "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
)

foreach ($task in $tasksToDisable) {
    try {
        schtasks /Change /TN $task /Disable | Out-Null
    } catch {}
}

# ==============================
# 3. Disable hibernation
# ==============================
Write-Host "Disabling hibernation..."
powercfg -h off

# ==============================
# 4. Set High Performance power plan
# ==============================
Write-Host "Setting High Performance power plan..."
powercfg /setactive SCHEME_MIN

# Disable disk sleep
powercfg /change disk-timeout-ac 0
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0

# ==============================
# 5. Optimize memory / crash dump
# ==============================
Write-Host "Optimizing memory dump settings..."

# Disable full memory dump, use small dump only
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" `
/v CrashDumpEnabled /t REG_DWORD /d 3 /f | Out-Null

# Disable automatic restart after crash
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" `
/v AutoReboot /t REG_DWORD /d 0 /f | Out-Null

# ==============================
# 6. Disable unnecessary visual performance globally
# ==============================
Write-Host "Setting system-wide best performance visual settings..."

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" `
/v VisualFXSetting /t REG_DWORD /d 2 /f | Out-Null

reg add "HKCU\Control Panel\Desktop" `
/v DragFullWindows /t REG_SZ /d 0 /f | Out-Null

reg add "HKCU\Control Panel\Desktop\WindowMetrics" `
/v MinAnimate /t REG_SZ /d 0 /f | Out-Null

# ==============================
# 7. Disable Server Manager auto-start
# ==============================
Write-Host "Disabling Server Manager auto-start..."

reg add "HKCU\Software\Microsoft\ServerManager" `
/v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f | Out-Null

reg add "HKLM\SOFTWARE\Microsoft\ServerManager" `
/v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f | Out-Null

# ==============================
# 8. Disable IPv6 transition technologies
# Safe for most VPS/VM automation use cases
# ==============================
Write-Host "Disabling IPv6 transition technologies..."

netsh interface teredo set state disabled | Out-Null
netsh interface 6to4 set state disabled | Out-Null
netsh interface isatap set state disabled | Out-Null

# ==============================
# 9. VMware tools check
# ==============================
Write-Host "Checking VMware Tools service..."

$vmTools = Get-Service -Name "VMTools" -ErrorAction SilentlyContinue
if ($vmTools) {
    Set-Service -Name "VMTools" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "VMTools" -ErrorAction SilentlyContinue
    Write-Host "VMware Tools service enabled." -ForegroundColor Green
} else {
    Write-Host "VMware Tools not detected. Install VMware Tools from ESXi for best performance." -ForegroundColor Yellow
}

# ==============================
# 10. Network tuning for VM
# ==============================
Write-Host "Applying network performance tuning..."

# Enable RSS if supported
Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        Enable-NetAdapterRss -Name $_.Name -ErrorAction SilentlyContinue
    } catch {}
}

# TCP tuning
netsh int tcp set global autotuninglevel=normal | Out-Null
netsh int tcp set global rss=enabled | Out-Null
netsh int tcp set global ecncapability=disabled | Out-Null
netsh int tcp set global timestamps=disabled | Out-Null

# ==============================
# 11. Disable background apps policy
# ==============================
Write-Host "Disabling background apps policy..."

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" `
/v LetAppsRunInBackground /t REG_DWORD /d 2 /f | Out-Null

# ==============================
# 12. Reduce Windows tips / consumer features
# ==============================
Write-Host "Disabling Windows tips and consumer features..."

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" `
/v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f | Out-Null

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
/v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f | Out-Null


# ------------------------------
# RDP STATIC ROUTING BYPASS VPN
# Tujuan: koneksi RDP tetap lewat gateway utama, bukan route VPN
# ------------------------------
Write-Host "Configuring RDP static routing bypass VPN..." -ForegroundColor Cyan

$RdpPort = 3889

# Ambil interface dengan default gateway utama sebelum/selain VPN
$MainRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
    Where-Object {
        $_.NextHop -ne "0.0.0.0" -and
        $_.RouteMetric -lt 5000
    } |
    Sort-Object RouteMetric |
    Select-Object -First 1

if ($MainRoute) {
    $MainInterfaceIndex = $MainRoute.InterfaceIndex
    $MainGateway        = $MainRoute.NextHop

    Write-Host "Main Interface Index : $MainInterfaceIndex" -ForegroundColor Green
    Write-Host "Main Gateway         : $MainGateway" -ForegroundColor Green

    # Turunkan prioritas route utama supaya tetap menang untuk management
    Set-NetIPInterface -InterfaceIndex $MainInterfaceIndex -AutomaticMetric Disabled -InterfaceMetric 10

    # Cari adapter VPN dan buat metric lebih besar
    Get-NetIPInterface -AddressFamily IPv4 | Where-Object {
        $_.InterfaceAlias -match "VPN|TAP|WireGuard|OpenVPN|Tailscale|ZeroTier|Pangolin|Tunnel"
    } | ForEach-Object {
        Write-Host "Setting VPN interface metric high: $($_.InterfaceAlias)"
        Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AutomaticMetric Disabled -InterfaceMetric 5000
    }

    # Firewall allow RDP 3889 dari semua IP / bisa diganti RemoteAddress tertentu
    Get-NetFirewallRule -DisplayName "Allow RDP Static Bypass VPN" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    New-NetFirewallRule `
        -DisplayName "Allow RDP Static Bypass VPN" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort $RdpPort `
        -Action Allow `
        -Profile Any | Out-Null

    Write-Host "RDP static routing bypass VPN applied." -ForegroundColor Green
} else {
    Write-Host "Main default gateway not found. Static bypass skipped." -ForegroundColor Red
}
# Ganti port RDP
$NewPort = 3889

Set-ItemProperty `
-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
-Name "PortNumber" -Value $NewPort

Write-Host "RDP port changed to $NewPort"

# Hapus rule lama (3389)
Get-NetFirewallRule -DisplayName "RDP OLD" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# Tambah rule baru
New-NetFirewallRule `
-DisplayName "RDP $NewPort" `
-Direction Inbound `
-Protocol TCP `
-LocalPort $NewPort `
-Action Allow

# Install SNMP
Install-WindowsFeature SNMP-Service -IncludeManagementTools

# Set community string
$community = "gokil"

$snmpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
New-Item -Path $snmpPath -Force | Out-Null
New-ItemProperty -Path $snmpPath -Name $community -PropertyType DWord -Value 4 -Force | Out-Null

# Allow monitoring manager
# Ganti IP ini ke IP Zabbix/LibreNMS/NMS kamu
$monitoringIP = "192.168.92.100"

$managerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
New-Item -Path $managerPath -Force | Out-Null
New-ItemProperty -Path $managerPath -Name "1" -PropertyType String -Value $monitoringIP -Force | Out-Null

# Enable service
Set-Service SNMP -StartupType Automatic
Restart-Service SNMP

# Open firewall UDP 161
New-NetFirewallRule `
  -DisplayName "SNMP UDP 161" `
  -Direction Inbound `
  -Protocol UDP `
  -LocalPort 161 `
  -RemoteAddress $monitoringIP `
  -Action Allow
  
# ==============================
# DONE
# ==============================
Write-Host "VMware ESXi Windows Server lightweight optimization applied." -ForegroundColor Green
Write-Host "Reboot recommended after VMware/Performance tuning." -ForegroundColor Yellow

Write-Host " VM Perf  : VMware ESXi lightweight optimization enabled" -ForegroundColor Cyan
Write-Host " Services : SysMain, Search, Telemetry, Error Reporting disabled" -ForegroundColor Cyan
Write-Host " Power    : High Performance mode enabled" -ForegroundColor Cyan

Restart-Service TermService -Force
