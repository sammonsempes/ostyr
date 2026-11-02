#!/usr/bin/env bash
# Shared helpers for lab/up.sh and lab/down.sh. Sourced, never run.

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$LAB_DIR")"
export REPO_DIR
LAB_POOL="${LAB_POOL:-ostyr-lab}"
LAB_POOL_PATH="${LAB_POOL_PATH:-/var/lib/libvirt/images/$LAB_POOL}"
LAB_STATE_ROOT="$LAB_DIR/state"
LAB_URI="qemu:///system"
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
        tofu -chdir="$LAB_DIR/tofu" "$@"
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
