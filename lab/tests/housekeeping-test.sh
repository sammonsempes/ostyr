#!/usr/bin/env bash
# Usage: lab/tests/housekeeping-test.sh
# Checks profile validation, the stale-image warning (back-dated .built volume) and lab/images/prune.sh. Needs libvirt.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly STALE_IMAGE="tstale-image.qcow2"
readonly ORPHAN_IMAGE="torphan-image.qcow2"
readonly OLD_AGE_SECONDS=1728000
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

fails() {
    ! "$@"
}

work_dir="$(mktemp -d)"
cleanup() {
    local volume
    for volume in "$STALE_IMAGE" "$STALE_IMAGE.built" "$ORPHAN_IMAGE" "$ORPHAN_IMAGE.built"; do
        virsh_lab vol-delete --pool "$LAB_POOL" "$volume" >/dev/null 2>&1 || log "cleanup: $volume already gone"
    done
    rm -rf "$work_dir"
}
trap cleanup EXIT

create_volume() {
    virsh_lab vol-create-as "$LAB_POOL" "$1" "$VOLUME_SIZE" --format "$2" >/dev/null
}

printf 'vms:\n  - name: Bad_Name\n    ssh_user: ubuntu\n' >"$work_dir/bad-name.yaml"
printf 'vms:\n  - name: good\n    ssh_user: "x;id"\n' >"$work_dir/bad-user.yaml"
printf 'vms:\n  - name: good\n    ssh_user: ubuntu\n' >"$work_dir/good.yaml"

check "profile name with uppercase rejected" fails bash -c 'source "$1"; validate_profile_name "Bad_Name"' _ "$LAB_DIR/lib.sh"
check "profile name path rejected" fails bash -c 'source "$1"; validate_profile_name "../x"' _ "$LAB_DIR/lib.sh"
check "profile name accepted" bash -c 'source "$1"; validate_profile_name "ubuntu-pair"' _ "$LAB_DIR/lib.sh"
check "bad VM name rejected" fails bash -c 'source "$1"; validate_profile_fields "$2"' _ "$LAB_DIR/lib.sh" "$work_dir/bad-name.yaml"
check "bad ssh_user rejected" fails bash -c 'source "$1"; validate_profile_fields "$2"' _ "$LAB_DIR/lib.sh" "$work_dir/bad-user.yaml"
check "good profile accepted" bash -c 'source "$1"; validate_profile_fields "$2"' _ "$LAB_DIR/lib.sh" "$work_dir/good.yaml"
check "shipped profiles accepted" bash -c 'source "$1"; for f in "$(dirname "$1")"/profiles/*.yaml; do validate_profile_fields "$f"; done' _ "$LAB_DIR/lib.sh"

ensure_pool
create_volume "$STALE_IMAGE" qcow2
create_volume "$STALE_IMAGE.built" raw
printf '%s\n' "$(($(date +%s) - OLD_AGE_SECONDS))" >"$work_dir/built"
virsh_lab vol-upload --pool "$LAB_POOL" "$STALE_IMAGE.built" "$work_dir/built"
warning="$(warn_if_stale "$STALE_IMAGE" 2>&1)"
check "stale image warns" grep -q "days old" <<<"$warning"

create_volume "$ORPHAN_IMAGE" qcow2
create_volume "$ORPHAN_IMAGE.built" raw
"$LAB_DIR/images/prune.sh"
check "unreferenced base volume pruned" fails virsh_lab vol-info --pool "$LAB_POOL" "$ORPHAN_IMAGE"
check "its stamp pruned" fails virsh_lab vol-info --pool "$LAB_POOL" "$ORPHAN_IMAGE.built"
check "referenced base volume kept" virsh_lab vol-info --pool "$LAB_POOL" ubuntu-2404.qcow2

exit "$((failures > 0))"
