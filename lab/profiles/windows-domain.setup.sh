#!/usr/bin/env bash
# Usage: lab/profiles/windows-domain.setup.sh <lab-state-dir> <lab-prefix>
# Run by up.sh once every VM answers SSH: promotes the DC for lab.ostyr.test, then joins the workstation to it.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly DOMAIN_NAME="lab.ostyr.test"
readonly DOMAIN_NETBIOS="LAB"
readonly READY_ATTEMPTS=180
readonly READY_DELAY_SECONDS=5
readonly DC_PASSWORD_BYTES=12

lab_state="${1:?usage: windows-domain.setup.sh <lab-state-dir> <lab-prefix>}"
key="$lab_state/id_ed25519"
read -r _ dc_user dc_address < <(awk '$1 == "dc"' "$lab_state/vms.txt")
read -r _ ws_user ws_address < <(awk '$1 == "ws"' "$lab_state/vms.txt")
[[ -n "$dc_address" && -n "$ws_address" ]] || die "vms.txt lacks the dc and ws VMs"
admin_password="Aa1-$(openssl rand -hex "$DC_PASSWORD_BYTES")"
printf '%s\n' "$admin_password" >"$lab_state/domain_admin_password"
chmod 600 "$lab_state/domain_admin_password"

ps_remote() {
    local user="$1" address="$2" script="$3"
    ssh -n -i "$key" -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        "$user@$address" "powershell -NoProfile -NonInteractive -EncodedCommand $(printf '%s' "\$ProgressPreference = 'SilentlyContinue'; $script" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)"
}

boot_time() {
    ps_remote "$1" "$2" '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.Ticks' | tr -d '\r'
}

wait_until() {
    local description="$1"
    shift
    local attempt
    for ((attempt = 0; attempt < READY_ATTEMPTS; attempt++)); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep "$READY_DELAY_SECONDS"
    done
    die "timed out waiting for $description"
}

booted_after() {
    local user="$1" address="$2" before="$3" now
    now="$(boot_time "$user" "$address")"
    [[ "$now" =~ ^[0-9]+$ && "$now" != "$before" ]]
}

static_address_template='$nic = Get-NetAdapter | Where-Object Status -eq Up | Select-Object -First 1
$cfg = Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | Select-Object -First 1
$inner = "Set-NetIPInterface -InterfaceIndex $($nic.ifIndex) -Dhcp Disabled; Get-NetIPAddress -InterfaceIndex $($nic.ifIndex) -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:`$false -ErrorAction SilentlyContinue; New-NetIPAddress -InterfaceIndex $($nic.ifIndex) -IPAddress $($cfg.IPAddress) -PrefixLength $($cfg.PrefixLength) | Out-Null; Set-DnsClientServerAddress -InterfaceIndex $($nic.ifIndex) -ServerAddresses __DNS__"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -EncodedCommand $encoded"
Register-ScheduledTask -TaskName ostyr-static-address -Action $action -User SYSTEM -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName ostyr-static-address'

make_static() {
    local user="$1" address="$2" dns="$3"
    ps_remote "$user" "$address" "${static_address_template//__DNS__/$dns}"
    sleep "$READY_DELAY_SECONDS"
    wait_until "a static address on $address" ps_remote "$user" "$address" \
        "if ((Get-NetIPInterface -AddressFamily IPv4 | Where-Object InterfaceAlias -notlike 'Loopback*').Dhcp -ne 'Disabled') { exit 1 }"
}

log "dc: static address and domain promotion"
dc_boot="$(boot_time "$dc_user" "$dc_address")"
make_static "$dc_user" "$dc_address" "$dc_address"
ps_remote "$dc_user" "$dc_address" "\$secure = ConvertTo-SecureString '$admin_password' -AsPlainText -Force; \
Enable-LocalUser -Name Administrator; Set-LocalUser -Name Administrator -Password \$secure; \
Install-ADDSForest -DomainName $DOMAIN_NAME -DomainNetbiosName $DOMAIN_NETBIOS -SafeModeAdministratorPassword \$secure -InstallDns -NoRebootOnCompletion:\$false -Force" ||
    log "dc: session ended by the promotion reboot"
wait_until "the DC to reboot" booted_after Administrator "$dc_address" "$dc_boot"
wait_until "Active Directory on the DC" ps_remote Administrator "$dc_address" "(Get-ADDomain).DNSRoot"
sed -i "s/^dc $dc_user /dc Administrator /" "$lab_state/vms.txt"

log "ws: resolver and domain join"
ws_boot="$(boot_time "$ws_user" "$ws_address")"
make_static "$ws_user" "$ws_address" "$dc_address"
wait_until "the lab domain to resolve from the workstation" ps_remote "$ws_user" "$ws_address" "Resolve-DnsName $DOMAIN_NAME -ErrorAction Stop"
ps_remote "$ws_user" "$ws_address" "\$secure = ConvertTo-SecureString '$admin_password' -AsPlainText -Force; \
\$credential = New-Object System.Management.Automation.PSCredential('$DOMAIN_NETBIOS\\Administrator', \$secure); \
Add-Computer -DomainName $DOMAIN_NAME -Credential \$credential -Restart -Force" ||
    log "ws: session ended by the join reboot"
wait_until "the workstation to reboot" booted_after "$ws_user" "$ws_address" "$ws_boot"
log "windows-domain ready: $DOMAIN_NAME, domain admin password in $lab_state/domain_admin_password"
