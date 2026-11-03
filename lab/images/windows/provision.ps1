$ErrorActionPreference = 'Stop'
$cloudbaseDir = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init'
if ($env:OSTYR_IMAGE -eq 'ws2022-dc') {
    Install-WindowsFeature -Name AD-Domain-Services, DNS, RSAT-AD-Tools, RSAT-DNS-Server -IncludeManagementTools | Out-Null
}
Start-Process -FilePath msiexec.exe -Wait -ArgumentList '/i', 'C:\Windows\Temp\cloudbase-init.msi', '/qn', '/l*v', 'C:\Windows\Temp\cloudbase-msi.log', 'USERNAME=labadmin', 'RUN_SERVICE_AS_LOCAL_SYSTEM=1'
Stop-Service -Name cloudbase-init -ErrorAction SilentlyContinue
Copy-Item -Force 'C:\Windows\Temp\cloudbase-init.conf' (Join-Path $cloudbaseDir 'conf\cloudbase-init.conf')
Copy-Item -Force 'C:\Windows\Temp\cloudbase-init.conf' (Join-Path $cloudbaseDir 'conf\cloudbase-init-unattend.conf')
Set-Service -Name cloudbase-init -StartupType Automatic
if (-not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker')) {
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker' | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker' -Name PreventDeviceEncryption -Value 1 -PropertyType DWord -Force | Out-Null
if (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Profile Any -Enabled True
} else {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any | Out-Null
}
Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' | Select-Object Name, Enabled, Profile | Format-List
Update-MpSignature
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureVersion | Format-List
