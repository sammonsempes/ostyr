$ErrorActionPreference = 'Stop'
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null
$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
(Get-Content $sshdConfig) -replace '^#?PasswordAuthentication .*', 'PasswordAuthentication no' | Set-Content $sshdConfig -Encoding ascii
mountvol.exe S: /S
New-Item -ItemType Directory -Force -Path 'S:\EFI\Boot' | Out-Null
Copy-Item -Force 'S:\EFI\Microsoft\Boot\bootmgfw.efi' 'S:\EFI\Boot\bootx64.efi'
mountvol.exe S: /D
Remove-Item -Force (Join-Path $env:ProgramData 'ssh\administrators_authorized_keys')
Disable-LocalUser -Name Administrator
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword, AutoAdminLogon -ErrorAction SilentlyContinue
Remove-Item -Force -ErrorAction SilentlyContinue C:\Windows\Temp\cloudbase-init.msi, C:\Windows\Panther\unattend.xml, C:\Windows\Panther\Unattend\Unattend.xml
Remove-LocalUser -Name packer
shutdown.exe /s /t 5 /f
