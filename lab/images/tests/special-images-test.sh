#!/usr/bin/env bash
# Usage: [SPECIAL_TASK=<lab id>] [SPECIAL_SKIP_BUILD=1] lab/images/tests/special-images-test.sh [--static]
# Builds k3s-node, backup-server, attacker and ubuntu-2404, boots base-special and attack-linux, checks each image, runs one harmless Atomic test.
# --static only validates the three templates and the egress script.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../../lib.sh"

readonly TEST_TASK="${SPECIAL_TASK:-TSPECTEST}"
readonly IMAGES_DIR="$LAB_DIR/images"
readonly HTTP_PORT=8000
readonly OUTSIDE_ADDRESS="1.1.1.1"
readonly CONNECT_TIMEOUT=5
readonly K3S_ATTEMPTS=60
readonly K3S_DELAY_SECONDS=5
readonly LAN_PORTS="22 53 80 443"
readonly ATOMIC_TEST_NAME="Linux Download File and Run"

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

check_not() {
    local description="$1"
    shift
    if "$@"; then
        log "FAIL $description"
        failures=$((failures + 1))
    else
        log "ok   $description"
    fi
}

work_dir="$(mktemp -d)"
cleanup() {
    "$LAB_DIR/down.sh" "$TEST_TASK" >/dev/null 2>&1 || log "cleanup failed"
    rm -rf "$work_dir"
}
trap cleanup EXIT

ssh_vm() {
    local name="$1"
    shift
    local vm_user vm_address
    read -r _ vm_user vm_address < <(awk -v name="$name" '$1 == name' "$lab_state/vms.txt")
    ssh -n -i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        "$vm_user@$vm_address" "$@"
}

k3s_pods_ready() {
    local attempt pending pods
    for ((attempt = 0; attempt < K3S_ATTEMPTS; attempt++)); do
        pods="$(ssh_vm k3s "k3s kubectl get pods -n kube-system --no-headers 2>/dev/null | wc -l")" || pods=0
        pending="$(ssh_vm k3s "k3s kubectl get pods -n kube-system --no-headers 2>/dev/null | awk '\$3 != \"Running\" && \$3 != \"Completed\"' | wc -l")" || pending=1
        if [[ "$pending" == "0" && "$pods" -gt 0 ]]; then
            return 0
        fi
        sleep "$K3S_DELAY_SECONDS"
    done
    ssh_vm k3s "k3s kubectl get pods -A" || log "cannot list pods"
    return 1
}

ssh-keygen -q -t ed25519 -N '' -f "$work_dir/key"
for image in k3s-node backup-server attacker; do
    check "packer validate $image" packer validate \
        -var "ssh_private_key_file=$work_dir/key" -var "ssh_public_key=$(cat "$work_dir/key.pub")" "$IMAGES_DIR/$image.pkr.hcl"
done
check "packer fmt -check" packer fmt -check "$IMAGES_DIR"
check "egress script passes bash -n" bash -n "$IMAGES_DIR/attacker/ostyr-attacker-egress"
check "ubuntu-2404 installs rsyslog-gnutls" grep -q 'rsyslog-gnutls' "$IMAGES_DIR/ubuntu-2404.pkr.hcl"

if [[ "${1:-}" != "--static" ]]; then
    for image in ubuntu-2404 k3s-node backup-server attacker; do
        [[ "${SPECIAL_SKIP_BUILD:-0}" == "1" ]] && continue
        check "build $image" "$IMAGES_DIR/build.sh" "$image"
    done

    export LAB_PROFILE="base-special"
    "$LAB_DIR/up.sh" "$TEST_TASK"
    lab_state="$(state_dir "$TEST_TASK")"
    check "k3s binary runs" grep -q 'k3s version' <(ssh_vm k3s k3s --version)
    check "k3s airgap images baked" ssh_vm k3s 'ls /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar.zst'
    check_not "k3s service is not enabled" ssh_vm k3s systemctl is-enabled --quiet k3s
    check_not "k3s node has no default route" test -n "$(ssh_vm k3s ip -4 route show default)"
    ssh_vm k3s sudo systemctl start k3s
    check "k3s kube-system pods all Running or Completed" k3s_pods_ready
    check "restic runs" ssh_vm backup restic version
    check "borg runs" ssh_vm backup borg --version
    check "backupsvc user password locked" grep -q ' L ' <(ssh_vm backup sudo passwd -S backupsvc)
    check "ubuntu password locked" grep -q ' L ' <(ssh_vm backup sudo passwd -S ubuntu)
    "$LAB_DIR/down.sh" "$TEST_TASK"

    export LAB_PROFILE="attack-linux"
    "$LAB_DIR/up.sh" "$TEST_TASK"
    lab_state="$(state_dir "$TEST_TASK")"
    read -r _ _ target_address < <(awk '$1 == "target"' "$lab_state/vms.txt")
    host_gateway="$(ip -4 route show default | awk '{print $3; exit}')"
    host_lan_address="$(ip -4 route get "$OUTSIDE_ADDRESS" | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}')"
    bridge_address="${target_address%.*}.1"
    check "target has rsyslog-gnutls" ssh_vm target dpkg -s rsyslog-gnutls
    check "attacker has pwsh" grep -q 'PowerShell 7' <(ssh_vm attacker pwsh --version)
    check "attacker egress service active" ssh_vm attacker systemctl is-active --quiet ostyr-attacker-egress
    check_not "attacker cannot reach $OUTSIDE_ADDRESS" ssh_vm attacker curl --silent --max-time "$CONNECT_TIMEOUT" "https://$OUTSIDE_ADDRESS"
    for lan_address in "$bridge_address" "$host_lan_address" "$host_gateway"; do
        for lan_port in $LAN_PORTS; do
            check_not "attacker cannot reach $lan_address:$lan_port" ssh_vm attacker nc -z -w "$CONNECT_TIMEOUT" "$lan_address" "$lan_port"
        done
    done
    check "attacker reaches the target" ssh_vm attacker ping -c 1 -W "$CONNECT_TIMEOUT" "$target_address"
    ssh_vm target "mkdir -p /tmp/www && printf '#!/bin/sh\necho atomic-ran\n' >/tmp/www/atomic.sh"
    ssh_vm target "nohup python3 -m http.server $HTTP_PORT --directory /tmp/www >/tmp/http.log 2>&1 </dev/null &"
    ssh_vm attacker "pwsh -NoProfile -Command \"Import-Module /opt/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1 -Force; \
Invoke-AtomicTest T1105 -PathToAtomicsFolder /opt/AtomicRedTeam/atomics -TestNames '$ATOMIC_TEST_NAME' \
-InputArgs @{remote_url='http://$target_address:$HTTP_PORT/atomic.sh'}\""
    check "target logged the atomic download" ssh_vm target "grep -q 'GET /atomic.sh' /tmp/http.log"
    "$LAB_DIR/down.sh" "$TEST_TASK"
fi

exit "$((failures > 0))"
