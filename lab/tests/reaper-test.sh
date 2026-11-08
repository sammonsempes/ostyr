#!/usr/bin/env bash
# Usage: lab/tests/reaper-test.sh
# Defines an expired and a fresh lab (domain with creation metadata + overlay volume), runs the reaper, checks only the fresh one is left. Needs libvirt.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly OLD_TASK="TREAPOLD"
readonly NEW_TASK="TREAPNEW"
readonly TTL_MINUTES=60
readonly OLD_AGE_SECONDS=36000
readonly VOLUME_SIZE="1M"

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
    LAB_REAPER_ACTIVE=1 "$LAB_DIR/down.sh" "$OLD_TASK" >/dev/null 2>&1 || log "cleanup of $OLD_TASK failed"
    LAB_REAPER_ACTIVE=1 "$LAB_DIR/down.sh" "$NEW_TASK" >/dev/null 2>&1 || log "cleanup of $NEW_TASK failed"
    rm -rf "$work_dir"
}
trap cleanup EXIT

define_lab() {
    local task="$1" created="$2"
    local prefix
    prefix="$(lab_prefix "$task")"
    cat >"$work_dir/$task.xml" <<EOF
<domain type='$([[ "$(lab_accel)" == kvm ]] && echo kvm || echo qemu)'>
  <name>$prefix-vm</name>
  <memory unit='MiB'>16</memory>
  <os><type>hvm</type></os>
  <metadata>
    <ostyr:lab xmlns:ostyr="urn:ostyr:lab">
      <ostyr:task>$task</ostyr:task>
      <ostyr:created>$created</ostyr:created>
    </ostyr:lab>
  </metadata>
</domain>
EOF
    virsh_lab define "$work_dir/$task.xml" >/dev/null
    virsh_lab vol-create-as "$LAB_POOL" "$prefix-vm.qcow2" "$VOLUME_SIZE" --format qcow2 >/dev/null
}

domain_exists() { virsh_lab list --all --name | awk -v n="$1" '$0 == n' | grep -q .; }
volume_exists() { virsh_lab vol-info --pool "$LAB_POOL" "$1" >/dev/null 2>&1; }

ensure_pool
old_prefix="$(lab_prefix "$OLD_TASK")"
new_prefix="$(lab_prefix "$NEW_TASK")"
define_lab "$OLD_TASK" "$(($(date +%s) - OLD_AGE_SECONDS))"
define_lab "$NEW_TASK" "$(date +%s)"

LAB_VM_TTL_MINUTES="$TTL_MINUTES" "$LAB_DIR/reaper.sh"

check "expired domain removed" test "$(domain_exists "$old_prefix-vm" && echo yes || echo no)" = no
check "expired overlay removed" test "$(volume_exists "$old_prefix-vm.qcow2" && echo yes || echo no)" = no
check "fresh domain kept" domain_exists "$new_prefix-vm"
check "fresh overlay kept" volume_exists "$new_prefix-vm.qcow2"

exit "$((failures > 0))"
