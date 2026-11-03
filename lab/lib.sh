#!/usr/bin/env bash
# Shared helpers for lab/up.sh and lab/down.sh. Sourced, never run.

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$LAB_DIR")"
export REPO_DIR
LAB_POOL="${LAB_POOL:-ostyr-lab}"
LAB_POOL_PATH="${LAB_POOL_PATH:-/var/lib/libvirt/images/$LAB_POOL}"
LAB_STATE_ROOT="$LAB_DIR/state"
LAB_URI="qemu:///system"
readonly SECONDS_PER_DAY=86400
readonly STALE_DAYS=7
readonly DESTROY_TIMEOUT_SECONDS=120
readonly KIB_PER_UNIT=4194304
PATH="$HOME/.local/bin:$PATH"
export PATH

log() {
    printf '%s\n' "$*" >&2
}

die() {
    log "error: $*"
    exit 1
}

virsh_lab() {
    virsh -c "$LAB_URI" "$@"
}

validate_task_id() {
    [[ "$1" =~ ^[A-Za-z0-9]+$ ]] || die "invalid task id '$1' (letters and digits only)"
}

validate_profile_name() {
    [[ "$1" =~ ^[a-z0-9-]+$ ]] || die "invalid profile name '$1' (lowercase letters, digits and hyphens only)"
}

validate_profile_fields() {
    local field value
    for field in name ssh_user; do
        while read -r value; do
            [[ "$value" =~ ^[a-z0-9-]+$ ]] || die "invalid profile $field '$value' in $1 (lowercase letters, digits and hyphens only)"
        done < <(awk -v key="$field:" '{sub(/^ *- */, "")} $1 == key {print $2}' "$1")
    done
}

validate_profile_choices() {
    local field_allowed field allowed value
    for field_allowed in "guest:linux|windows" "firmware:bios|uefi" "tpm:true|false" "memory_gb:4|8" "disk_gb:[0-9]+"; do
        field="${field_allowed%%:*}"
        allowed="${field_allowed#*:}"
        while read -r value; do
            [[ "$value" =~ ^($allowed)$ ]] || die "invalid profile $field '$value' in $1 (allowed: $allowed)"
        done < <(awk -v key="$field:" '{sub(/^ *- */, "")} $1 == key {print $2}' "$1")
    done
}

profile_units() {
    awk '/^  - name:/ {count += 1} $1 == "memory_gb:" {extra += $2 / 4 - 1} END {print count + extra}' "$1"
}

domain_units() {
    local memory_kib
    memory_kib="$(virsh_lab dominfo "$1" | awk '/^Max memory:/ {print $3}')"
    printf '%s' "$(((memory_kib + KIB_PER_UNIT - 1) / KIB_PER_UNIT))"
}

run_reaper() {
    if [[ -z "${LAB_REAPER_ACTIVE:-}" ]]; then
        "$LAB_DIR/reaper.sh" || log "reaper failed, continuing"
    fi
}

lab_prefix() {
    printf 'ostyr-%s' "$1"
}

state_dir() {
    printf '%s/%s' "$LAB_STATE_ROOT" "$1"
}

run_tofu() {
    local task_id="$1"
    shift
    mkdir -p "$LAB_STATE_ROOT/plugin-cache"
    TF_DATA_DIR="$(state_dir "$task_id")/data" TF_PLUGIN_CACHE_DIR="$LAB_STATE_ROOT/plugin-cache" TF_IN_AUTOMATION=1 \
        "${LAB_TOFU_BIN:-tofu}" -chdir="$LAB_DIR/tofu" "$@"
}

run_tofu_bounded() {
    local pid waited=0 limit="${LAB_DESTROY_TIMEOUT:-$DESTROY_TIMEOUT_SECONDS}"
    run_tofu "$@" &
    pid=$!
    while kill -0 "$pid" 2>/dev/null && ((waited < limit)); do
        sleep 1
        waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        pkill -KILL -P "$pid" || log "no child of $pid to kill"
        kill -KILL "$pid" || log "process $pid already gone"
        wait "$pid" || log "destroy killed after ${limit}s"
        false
    else
        wait "$pid"
    fi
}

ensure_pool() {
    if ! virsh_lab pool-info "$LAB_POOL" >/dev/null 2>&1; then
        virsh_lab pool-define-as "$LAB_POOL" dir --target "$LAB_POOL_PATH" >/dev/null
        virsh_lab pool-build "$LAB_POOL" >/dev/null
    fi
    if [[ "$(virsh_lab pool-info "$LAB_POOL" | awk '/^State:/ {print $2}')" != "running" ]]; then
        virsh_lab pool-start "$LAB_POOL" >/dev/null
    fi
    virsh_lab pool-autostart "$LAB_POOL" >/dev/null
}

names_with_prefix() {
    awk -v prefix="$1" 'index($0, prefix) == 1'
}

volume_path() {
    virsh_lab vol-path --pool "$LAB_POOL" "$1"
}

overlays_of() {
    local base_path="$1"
    local name
    virsh_lab vol-list --pool "$LAB_POOL" | awk 'NR > 2 && NF {print $1}' | while read -r name; do
        virsh_lab vol-dumpxml --pool "$LAB_POOL" "$name" | awk -v base="$base_path" -v name="$name" \
            '/<backingStore>/ {inside = 1} inside && index($0, "<path>" base "</path>") {print name} /<\/backingStore>/ {inside = 0}'
    done
}

warn_if_stale() {
    local stamp_file built_at age_days
    stamp_file="$(mktemp)"
    if virsh_lab vol-download --pool "$LAB_POOL" "$1.built" "$stamp_file" >/dev/null 2>&1 && built_at="$(cat "$stamp_file")" &&
        [[ "$built_at" =~ ^[0-9]+$ ]]; then
        age_days=$((($(date +%s) - built_at) / SECONDS_PER_DAY))
        if ((age_days > STALE_DAYS)); then
            log "warning: base image $1 is $age_days days old (built $(date -d "@$built_at" --iso-8601=date)), rebuild with lab/images/build.sh ${1%.qcow2}"
        fi
    else
        log "warning: base image $1 has no recorded build date, rebuild with lab/images/build.sh ${1%.qcow2}"
    fi
    rm -f "$stamp_file"
}
