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
for template in "$IMAGES_DIR"/*.pkr.hcl; do
    check "packer validate $(basename "$template")" packer validate \
        -var "ssh_private_key_file=$work_dir/key" -var "ssh_public_key=$(cat "$work_dir/key.pub")" "$template"
done

if [[ "${1:-}" != "--static" ]]; then
    export LAB_PROFILE="ubuntu-single"
    check "build" "$IMAGES_DIR/build.sh" ubuntu-2404
    "$LAB_DIR/up.sh" "$TEST_TASK"
    lab_state="$(state_dir "$TEST_TASK")"
    read -r _ vm_user vm_address <"$lab_state/vms.txt"
    ssh_vm() {
        ssh -i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            "$vm_user@$vm_address" "$@"
    }
    check "cloud-init status done" grep -q 'status: done' <(ssh_vm cloud-init status --wait)
    check "guest agent enabled" ssh_vm systemctl is-enabled qemu-guest-agent
    check "password locked" grep -q ' L ' <(ssh_vm sudo passwd -S ubuntu)
    check "build date recorded" virsh_lab vol-info --pool "$LAB_POOL" ubuntu-2404.qcow2.built
    "$LAB_DIR/down.sh" "$TEST_TASK"
    check "base volume untouched" virsh_lab vol-info --pool "$LAB_POOL" ubuntu-2404.qcow2
fi

exit "$((failures > 0))"
