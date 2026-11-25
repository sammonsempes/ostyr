#!/usr/bin/env bash
# Usage: lab/images/tests/rustdesk-relay-test.sh <task-id>
# On a booted rustdesk-relay lab (LAB_PROFILE=rustdesk-relay lab/up.sh <task-id>): both units are active and run as the rustdesk user with the key
# required (-k _), the key file is mode 0600, no listener other than sshd and the RustDesk ports exists, no RustDesk port answers HTTP, and the VM
# firewall lets only the three relay-needed ports and udp 21116 through (the websocket ports 21118 and 21119 listen but are dropped, and so is the
# ephemeral udp socket hbbs opens: the listener check ignores that one socket, the firewall accepts no udp port but 21116).
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../../lib.sh"

readonly CONNECT_TIMEOUT=3
readonly READY_ATTEMPTS=30
readonly READY_DELAY_SECONDS=2
readonly KEY_FILE=/var/lib/rustdesk/id_ed25519
readonly OPEN_PORTS=(21115 21116 21117)
readonly CLOSED_PORTS=(21118 21119)
readonly ALLOWED_TCP_PORTS='22 21115 21116 21117 21118 21119'
readonly ALLOWED_UDP_PORTS='68 21116'

task_id="${1:?usage: rustdesk-relay-test.sh <task-id>}"
lab_state="$(state_dir "$task_id")"
read -r _ relay_user relay_address < <(awk '$1 == "relay"' "$lab_state/vms.txt")
[[ -n "$relay_address" ]] || die "vms.txt lacks the relay VM"
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

failures=0
check() {
    local description="$1"
    shift
    if "$@"; then
        log "ok   $description"
    else
        log "FAIL $description"
        failures=$((failures + 1))
    fi
}

relay() {
    ssh -n "${ssh_options[@]}" "$relay_user@$relay_address" "$@"
}

units_active() {
    local attempt
    for ((attempt = 0; attempt < READY_ATTEMPTS; attempt++)); do
        if relay systemctl is-active --quiet rustdesk-hbbs rustdesk-hbbr && relay sudo test -f "$KEY_FILE"; then
            return 0
        fi
        sleep "$READY_DELAY_SECONDS"
    done
    return 1
}

listener_ports() {
    local protocol="$1"
    relay "sudo ss -H -l -n -p -$protocol" |
        awk '{n = split($4, parts, ":"); if ($4 !~ /^(127\.|\[::1\])/ && !($0 ~ /"hbbs"/ && parts[n] != 21116 && $1 == "UNCONN")) print parts[n]}' |
        sort -un | tr '\n' ' '
}

http_status() {
    curl --silent --output /dev/null --max-time "$CONNECT_TIMEOUT" --write-out '%{http_code}' "http://$relay_address:$1/" || true
}

port_open() {
    nc -z -w "$CONNECT_TIMEOUT" "$relay_address" "$1"
}

port_closed() {
    ! port_open "$1"
}

no_http_answer() {
    local port status
    for port in "${OPEN_PORTS[@]}"; do
        status="$(http_status "$port")"
        [[ ! "$status" =~ ^[123] ]] || return 1
    done
}

check "both units active and the key file exists" units_active
check "hbbs runs as rustdesk with -k _ and ALWAYS_USE_RELAY" relay "pid=\$(systemctl show -p MainPID --value rustdesk-hbbs); \
    [ \"\$(ps -o user= -p \$pid)\" = rustdesk ] && tr '\\0' ' ' </proc/\$pid/cmdline | grep -q -- '/opt/ostyr/rustdesk/hbbs -k _ -r ' && \
    sudo cat /proc/\$pid/environ | tr '\\0' '\\n' | grep -qx ALWAYS_USE_RELAY=Y"
check "hbbr runs as rustdesk with -k _" relay "pid=\$(systemctl show -p MainPID --value rustdesk-hbbr); \
    [ \"\$(ps -o user= -p \$pid)\" = rustdesk ] && tr '\\0' ' ' </proc/\$pid/cmdline | grep -q -- '/opt/ostyr/rustdesk/hbbr -k _'"
check "key file is mode 600 owned by rustdesk" test "$(relay "sudo stat -c '%a %U' $KEY_FILE")" = "600 rustdesk"
check "binaries are root-owned" test "$(relay "stat -c '%U:%a' /opt/ostyr/rustdesk/hbbs /opt/ostyr/rustdesk/hbbr" | tr '\n' ' ')" = "root:755 root:755 "
log "tcp listeners: $(relay "sudo ss -H -l -n -t -p" | tr -s ' ' | cut -d' ' -f4,6 | tr '\n' ';')"
log "udp listeners: $(relay "sudo ss -H -l -n -u -p" | tr -s ' ' | cut -d' ' -f4,6 | tr '\n' ';')"
check "tcp listeners are sshd and RustDesk ports only" test "$(listener_ports t)" = "$ALLOWED_TCP_PORTS "
check "udp listeners are the DHCP client and RustDesk only" test "$(listener_ports u)" = "$ALLOWED_UDP_PORTS "
check "no RustDesk port answers HTTP" no_http_answer
for port in "${OPEN_PORTS[@]}"; do
    check "firewall lets tcp $port through" port_open "$port"
done
for port in "${CLOSED_PORTS[@]}"; do
    check "firewall drops tcp $port" port_closed "$port"
done
((failures == 0)) || die "$failures check(s) failed"
log "all rustdesk-relay checks passed"
