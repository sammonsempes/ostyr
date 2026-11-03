#!/usr/bin/env bash
# Usage: lab/images/tests/images-test.sh [--static]
# Runs packer fmt -check and validate on every template; unless --static, also builds ubuntu-2404, boots it through up.sh and checks cloud-init.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../../lib.sh"

readonly TEST_TASK="TIMGTEST"
readonly IMAGES_DIR="$LAB_DIR/images"

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

work_dir="$(mktemp -d)"
cleanup() {
    "$LAB_DIR/down.sh" "$TEST_TASK" >/dev/null 2>&1 || log "cleanup failed"
    rm -rf "$work_dir"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$work_dir/key"
check "packer fmt -check" packer fmt -check "$IMAGES_DIR"
mkdir -p "$work_dir/drivers/viostor" "$work_dir/drivers/NetKVM"
for template in "$IMAGES_DIR"/*.pkr.hcl; do
    extra_vars=()
    if [[ "$(basename "$template")" =~ ^(win|ws) ]]; then
        touch "$work_dir/cloudbase.msi"
        extra_vars=(-var "drivers_dir=$work_dir/drivers" -var "cloudbase_msi=$work_dir/cloudbase.msi")
    fi
    check "packer validate $(basename "$template")" packer validate \
        -var "ssh_private_key_file=$work_dir/key" -var "ssh_public_key=$(cat "$work_dir/key.pub")" "${extra_vars[@]}" "$template"
done
check "pins file is well formed" awk -F'\t' 'NF != 5 || $2 !~ /^[0-9a-f]{64}$/ {bad = 1} END {exit bad}' "$IMAGES_DIR/pins.tsv"
for pin in win11 ws2022 virtio-win cloudbase-init; do
    check "pin $pin present" grep -q "^$pin"$'\t' "$IMAGES_DIR/pins.tsv"
done

if [[ "${1:-}" != "--static" ]]; then
    export LAB_PROFILE="ubuntu-single"
    check "build" "$IMAGES_DIR/build.sh" ubuntu-2404
    "$LAB_DIR/up.sh" "$TEST_TASK"
    lab_state="$(state_dir "$TEST_TASK")"
    read -r _ vm_user vm_address <"$lab_state/vms.txt"
    ssh_vm() {
        ssh -n -i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            "$vm_user@$vm_address" "$@"
    }
    check "cloud-init status done" grep -q 'status: done' <(ssh_vm cloud-init status --wait)
    check "guest agent enabled" ssh_vm systemctl is-enabled qemu-guest-agent
    check "password locked" grep -q ' L ' <(ssh_vm sudo passwd -S ubuntu)
    check "build date recorded" virsh_lab vol-info --pool "$LAB_POOL" ubuntu-2404.qcow2.built
    "$LAB_DIR/down.sh" "$TEST_TASK"
    check "base volume untouched" virsh_lab vol-info --pool "$LAB_POOL" ubuntu-2404.qcow2

    export LAB_PROFILE="linux-matrix"
    for image in rocky-9 rocky-8 debian-12; do
        check "build $image" "$IMAGES_DIR/build.sh" "$image"
    done
    "$LAB_DIR/up.sh" "$TEST_TASK"
    while read -r vm_name vm_user vm_address; do
        kernel="$(ssh -n -i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            "$vm_user@$vm_address" uname -r)"
        log "$vm_name kernel $kernel"
        check "$vm_name cloud-init done" ssh -n -i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR "$vm_user@$vm_address" 'cloud-init status --wait | grep -q "status: done"'
        if [[ "$vm_name" == "rocky8" ]]; then
            check "rocky8 runs kernel 4.18" grep -q '^4\.18\.' <<<"$kernel"
        fi
    done <"$lab_state/vms.txt"
    "$LAB_DIR/down.sh" "$TEST_TASK"

    export LAB_PROFILE="windows-domain"
    for image in ws2022-dc win11; do
        check "build $image" "$IMAGES_DIR/build.sh" "$image"
    done
    "$LAB_DIR/up.sh" "$TEST_TASK"
    read -r _ dc_user dc_address < <(awk '$1 == "dc"' "$lab_state/vms.txt")
    read -r _ ws_user ws_address < <(awk '$1 == "ws"' "$lab_state/vms.txt")
    ssh_windows() {
        local user="$1" address="$2"
        shift 2
        ssh -n -i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            "$user@$address" "$@"
    }
    check "workstation is in the lab domain" grep -q 'lab.ostyr.test' <(ssh_windows "$ws_user" "$ws_address" '(Get-CimInstance Win32_ComputerSystem).Domain')
    check "workstation Defender real-time protection on" grep -q 'True' <(ssh_windows "$ws_user" "$ws_address" '(Get-MpComputerStatus).RealTimeProtectionEnabled')
    check "dc Defender real-time protection on" grep -q 'True' <(ssh_windows "$dc_user" "$dc_address" '(Get-MpComputerStatus).RealTimeProtectionEnabled')
    check "Sysmon not installed on the workstation" grep -q 'absent' <(ssh_windows "$ws_user" "$ws_address" 'if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {"present"} else {"absent"}')
    "$LAB_DIR/down.sh" "$TEST_TASK"

    export LAB_PROFILE="oidc-pair"
    check "build zitadel" "$IMAGES_DIR/build.sh" zitadel
    "$LAB_DIR/up.sh" "$TEST_TASK"
    read -r _ server_user server_address < <(awk '$1 == "server"' "$lab_state/vms.txt")
    check "server reads the discovery document with the lab CA" grep -q 'https://zitadel.lab.test' < <(ssh -n -i "$lab_state/id_ed25519" -o BatchMode=yes \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$server_user@$server_address" \
        'curl -s --cacert /etc/ostyr-lab/ca.pem https://zitadel.lab.test/.well-known/openid-configuration')
    for user_kind in mapped unmapped; do
        check "oidc-login.sh gets a code for the $user_kind user" grep -q '^code=' < <("$LAB_DIR/tests/oidc-login.sh" "$TEST_TASK" "$user_kind")
    done
    "$LAB_DIR/down.sh" "$TEST_TASK"
fi

exit "$((failures > 0))"
