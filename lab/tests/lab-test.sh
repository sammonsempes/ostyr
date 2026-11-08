#!/usr/bin/env bash
# Usage: lab/tests/lab-test.sh
# Runs up, checks VM count, isolation and overlay backing file, runs down, checks nothing is left. Needs a real libvirt host.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly TEST_TASK="${LAB_TEST_TASK:-TLABTEST}"
readonly PUBLIC_ADDRESS="1.1.1.1"

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

fails() {
    ! "$@"
}

prefix="$(lab_prefix "$TEST_TASK")"
export LAB_PROFILE="ubuntu-single"

cleanup() {
    "$LAB_DIR/down.sh" "$TEST_TASK" >/dev/null 2>&1 || log "cleanup failed"
}
trap cleanup EXIT

domain_count() { virsh_lab list --all --name | names_with_prefix "$prefix-" | wc -l; }
network_count() { virsh_lab net-list --all --name | awk -v n="$prefix" '$0 == n' | wc -l; }
volume_count() { virsh_lab vol-list --pool "$LAB_POOL" | awk '{print $1}' | names_with_prefix "$prefix-" | wc -l; }
running_domain_count() { virsh_lab list --state-running --name | names_with_prefix "$prefix-" | wc -l; }

host_gateway="$(ip -4 route show default | awk '{print $3; exit}')"
host_address="$(ip -4 -o addr show scope global | awk '$2 !~ /^(virbr|docker|br-)/ {split($4, a, "/"); print a[1]; exit}')"

check "quota refusal" fails env LAB_MAX_VMS=0 "$LAB_DIR/up.sh" "$TEST_TASK"
check "no domain after refusal" test "$(domain_count)" -eq 0
"$LAB_DIR/down.sh" "$TEST_TASK"

"$LAB_DIR/up.sh" "$TEST_TASK"
lab_state="$(state_dir "$TEST_TASK")"
read -r vm_name vm_user vm_address <"$lab_state/vms.txt"
ssh_vm() {
    ssh -i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        "$vm_user@$vm_address" "$@"
}

check "one running domain" test "$(running_domain_count)" -eq 1
expected_type=kvm
[[ "$(lab_accel)" == "kvm" ]] || expected_type=qemu
check "domain type matches the accelerator" grep -q "<domain type='$expected_type'" <(virsh_lab dumpxml "$prefix-$vm_name")
check "domain carries creation metadata" virsh_lab metadata "$prefix-$vm_name" --uri urn:ostyr:lab
check "network has no forward element" fails grep -q '<forward' <(virsh_lab net-dumpxml "$prefix")
check "VM has no default route" test -z "$(ssh_vm "ip route | awk '/^default/ {print \$3}'")"
check "Internet unreachable from VM" fails ssh_vm "ping -c 1 -W 2 $PUBLIC_ADDRESS"
check "LAN gateway unreachable from VM" fails ssh_vm "ping -c 1 -W 2 $host_gateway"
check "host address unreachable from VM" fails ssh_vm "ping -c 1 -W 2 $host_address"

bridge_address="${vm_address%.*}.1"
host_addresses="$(ip -4 -o addr show scope global | awk '{split($4, a, "/"); print a[1]}')"
probe_pairs() {
    local proto="$1" flag="$2"
    ss -H "$flag" -n | awk '{print $4}' | awk -v proto="$proto" -v addrs="$host_addresses" '
        { n = split($0, p, ":"); port = p[n]; address = substr($0, 1, length($0) - length(port) - 1); sub(/%.*/, "", address) }
        address ~ /^127\./ || address ~ /:/ { next }
        address == "0.0.0.0" || address == "*" { m = split(addrs, a, " "); for (i = 1; i <= m; i++) print proto, a[i], port; next }
        { print proto, address, port }' | sort -u
}
readonly UDP_UNREACHABLE_ERRNO=113
udp_probe_python="import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.connect((sys.argv[1], int(sys.argv[2])))
try:
    s.send(bytes(1))
    s.recv(1)
except OSError as error:
    sys.exit(0 if error.errno == $UDP_UNREACHABLE_ERRNO else 1)
sys.exit(1)"
mapfile -t tcp_pairs < <(probe_pairs tcp -ltn)
mapfile -t udp_pairs < <(probe_pairs udp -lun)
check "VM has nc and python3 for the probes" ssh_vm "command -v nc >/dev/null && command -v python3 >/dev/null"
force_route="sudo ip route replace default via $bridge_address"
tcp_script="command -v nc >/dev/null && $force_route"
for pair in "${tcp_pairs[@]}"; do
    read -r _ address port <<<"$pair"
    tcp_script+=" && ! nc -z -w 2 $address $port"
done
udp_script="command -v python3 >/dev/null && $force_route"
for pair in "${udp_pairs[@]}"; do
    read -r _ address port <<<"$pair"
    [[ "$address:$port" == "$bridge_address:67" ]] || udp_script+=" && python3 -c '$udp_probe_python' $address $port"
done
log "forced-route tcp probe: $tcp_script"
log "forced-route udp probe: $udp_script"
check "forced route: no listening tcp pair reachable" ssh_vm "$tcp_script"
check "forced route: no listening udp pair reachable (except dhcp on the bridge)" ssh_vm "$udp_script"
check "forced route: bridge tcp 22 unreachable" ssh_vm "$force_route; ! timeout 2 bash -c 'echo > /dev/tcp/$bridge_address/22'"
check "forced route: Internet still unreachable" fails ssh_vm "ping -c 1 -W 2 $PUBLIC_ADDRESS"

overlay_xml="$(virsh_lab vol-dumpxml --pool "$LAB_POOL" "$prefix-$vm_name.qcow2")"
check "overlay has a backing file" grep -q '<backingStore>' <<<"$overlay_xml"
check "overlay backs onto the base volume" grep -q 'ubuntu-2404.qcow2' <<<"$overlay_xml"

"$LAB_DIR/down.sh" "$TEST_TASK"
check "no domain left" test "$(domain_count)" -eq 0
check "no network left" test "$(network_count)" -eq 0
check "no volume left" test "$(volume_count)" -eq 0
check "state removed" test ! -e "$lab_state"
check "base volume untouched" virsh_lab vol-info --pool "$LAB_POOL" ubuntu-2404.qcow2
"$LAB_DIR/down.sh" "$TEST_TASK"

exit "$((failures > 0))"
