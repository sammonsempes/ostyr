#!/usr/bin/env bash
# Shared helpers for lab/up.sh and lab/down.sh. Sourced, never run.

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$LAB_DIR")"
export REPO_DIR
LAB_POOL="${LAB_POOL:-ostyr-lab}"
LAB_POOL_PATH="${LAB_POOL_PATH:-/var/lib/libvirt/images/$LAB_POOL}"
LAB_STATE_ROOT="$LAB_DIR/state"
LAB_LOCK_DIR="${LAB_LOCK_DIR:-$HOME/.cache/ostyr-lab/locks}"
LAB_PLUGIN_CACHE="${LAB_PLUGIN_CACHE:-$HOME/.cache/ostyr-lab/plugin-cache}"
LAB_URI="qemu:///system"
readonly SECONDS_PER_DAY=86400
readonly STALE_DAYS=7
readonly DESTROY_TIMEOUT_SECONDS=120
readonly KIB_PER_UNIT=4194304
readonly TCG_TIMEOUT_FACTOR=6
readonly PROXY_PORT=3128
readonly PROXY_MAX_CLIENTS=20
readonly PROXY_START_ATTEMPTS=20
readonly PROXY_LOG_MAX_BYTES=8388608
LAB_KVM_DEVICE="${LAB_KVM_DEVICE:-/dev/kvm}"
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

lab_accel() {
    local accel="${LAB_ACCEL:-}"
    if [[ -z "$accel" ]]; then
        if [[ -r "$LAB_KVM_DEVICE" && -w "$LAB_KVM_DEVICE" ]]; then accel=kvm; else accel=tcg; fi
    fi
    [[ "$accel" == "kvm" || "$accel" == "tcg" ]] || die "invalid LAB_ACCEL '$accel' (kvm or tcg)"
    printf '%s' "$accel"
}

accel_timeout_factor() {
    if [[ "$(lab_accel)" == "tcg" ]]; then printf '%s' "$TCG_TIMEOUT_FACTOR"; else printf '1'; fi
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
    TF_DATA_DIR="$(state_dir "$task_id")/data" TF_PLUGIN_CACHE_DIR="$LAB_PLUGIN_CACHE" TF_IN_AUTOMATION=1 \
        "${LAB_TOFU_BIN:-tofu}" -chdir="$LAB_DIR/tofu" "$@"
}

subnet_holder() {
    local network
    for network in $(virsh_lab net-list --all --name); do
        if virsh_lab net-dumpxml "$network" | grep -q "192\.168\.$1\."; then printf '%s ' "$network"; fi
    done
}

ensure_plugin_cache() {
    local main_repo seed
    mkdir -p "$LAB_PLUGIN_CACHE"
    if [[ -z "$(ls -A "$LAB_PLUGIN_CACHE")" ]]; then
        main_repo="$(dirname "$(git -C "$REPO_DIR" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || printf '%s/.git' "$REPO_DIR")")"
        seed="$main_repo/lab/state/plugin-cache"
        if [[ -d "$seed" && -n "$(ls -A "$seed")" ]]; then
            log "seeding the provider cache $LAB_PLUGIN_CACHE from $seed"
            cp -a "$seed/." "$LAB_PLUGIN_CACHE/"
        fi
    fi
}

acquire_lock() {
    local fd="$1" path="$2" holder
    if ! flock -n "$fd"; then
        holder="$(cat "$path" 2>/dev/null || true)"
        log "waiting for lock ${path##*/} held by task ${holder:-unknown}"
        flock "$fd"
    fi
    printf '%s\n' "$task_id" >"$path"
}

run_tofu_bounded() {
    local pid waited=0 limit="${BOUND_SECONDS:-${LAB_DESTROY_TIMEOUT:-$DESTROY_TIMEOUT_SECONDS}}"
    set -m
    run_tofu "$@" &
    pid=$!
    set +m
    while kill -0 "$pid" 2>/dev/null && ((waited < limit)); do
        sleep 1
        waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL -- "-$pid" || log "process group $pid already gone"
        wait "$pid" || log "bounded call killed after ${limit}s"
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

proxy_dir() {
    printf '%s/proxy' "$(state_dir "$1")"
}

profile_egress() {
    local egress
    egress="$(awk '$1 == "egress:" {print $2}' "$1")"
    [[ -z "$egress" ]] && egress=none
    [[ "$egress" == "proxy" || "$egress" == "none" ]] || die "invalid profile egress '$egress' in $1 (proxy or none)"
    if [[ "$egress" == "proxy" ]] && grep -Eq 'base_image: *attacker' "$1"; then
        die "egress: proxy is refused for attack profiles ($1)"
    fi
    printf '%s' "$egress"
}

proxy_filter_regexes() {
    awk 'NF {
        host = $1
        suffix = (substr(host, 1, 1) == ".")
        gsub(/\./, "\\.", host)
        if (suffix) { sub(/^\\\./, "", host); prefix = "([a-z0-9-]+\\.)*" } else { prefix = "" }
        print "^(http://)?" prefix host "(:(80|443))?(/|$)"
    }' "$1"
}

proxy_unit() {
    printf 'ostyr-proxy-%s.service' "$1"
}

proxy_start() {
    local task_id="$1" address="$2" dir unit attempt
    dir="$(proxy_dir "$task_id")"
    unit="$(proxy_unit "$task_id")"
    command -v ostyr-tinyproxy >/dev/null || die "ostyr-tinyproxy is missing, run sudo lab/host/install.sh"
    mkdir -p "$dir"
    proxy_filter_regexes "$LAB_DIR/egress-allow.txt" >"$dir/filter"
    install -m 0600 -o nobody -g nogroup /dev/null "$dir/proxy.log"
    cat >"$dir/tinyproxy.conf" <<CONF
User nobody
Group nogroup
Port $PROXY_PORT
Listen $address
Allow ${address%.1}.0/24
LogFile "$dir/proxy.log"
LogLevel Notice
MaxClients $PROXY_MAX_CLIENTS
ConnectPort 443
Filter "$dir/filter"
FilterType ere
FilterURLs Yes
FilterDefaultDeny Yes
DisableViaHeader Yes
CONF
    systemd-run --quiet --unit="${unit%.service}" \
        -p ProtectSystem=strict -p ProtectHome=tmpfs -p "BindPaths=$dir" -p "ReadWritePaths=$dir" -p PrivateDevices=yes \
        -p SystemCallFilter=@system-service -p PrivateTmp=yes -p NoNewPrivileges=yes \
        -p ProtectKernelTunables=yes -p ProtectControlGroups=yes -p RestrictAddressFamilies="AF_INET AF_UNIX" \
        -p CapabilityBoundingSet="CAP_SETUID CAP_SETGID" -p "LimitFSIZE=$PROXY_LOG_MAX_BYTES" \
        ostyr-tinyproxy -d -c "$dir/tinyproxy.conf"
    for ((attempt = 0; attempt < PROXY_START_ATTEMPTS; attempt++)); do
        if ss -ltn "src $address:$PROXY_PORT" | grep -q LISTEN; then return 0; fi
        sleep 1
    done
    die "proxy did not listen on $address:$PROXY_PORT"
}

proxy_stop() {
    local unit state
    unit="$(proxy_unit "$1")"
    state="$(systemctl is-failed "$unit" || true)"
    if [[ "$state" == "failed" ]]; then
        log "proxy of $1 was stopped by the host (log cap of $PROXY_LOG_MAX_BYTES bytes or a crash), see journalctl -u $unit"
    fi
    if systemctl is-active --quiet "$unit"; then systemctl stop "$unit"; fi
    if [[ "$state" == "failed" ]]; then systemctl reset-failed "$unit"; fi
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

base_versions() {
    virsh_lab vol-list --pool "$LAB_POOL" | awk 'NR > 2 && NF {print $1}' | { grep -E "^$1(-[0-9a-f]{12})?\.qcow2\$" || true; }
}

base_built_epoch() {
    local stamp_file epoch=0
    stamp_file="$(mktemp)"
    if virsh_lab vol-download --pool "$LAB_POOL" "$1.built" "$stamp_file" >/dev/null 2>&1 && [[ "$(cat "$stamp_file")" =~ ^[0-9]+$ ]]; then
        epoch="$(cat "$stamp_file")"
    fi
    rm -f "$stamp_file"
    printf '%s' "$epoch"
}

newest_base() {
    local volume
    base_versions "$1" | while read -r volume; do
        printf '%s %s\n' "$(base_built_epoch "$volume")" "$volume"
    done | sort -k1,1nr -k2,2 | awk 'NR == 1 {print $2}'
}

delete_base() {
    local suffix
    virsh_lab vol-delete --pool "$LAB_POOL" "$1" >/dev/null
    for suffix in built inputs; do
        if virsh_lab vol-info --pool "$LAB_POOL" "$1.$suffix" >/dev/null 2>&1; then
            virsh_lab vol-delete --pool "$LAB_POOL" "$1.$suffix" >/dev/null
        fi
    done
}

gc_bases() {
    local newest volume
    newest="$(newest_base "$1")"
    base_versions "$1" | while read -r volume; do
        if [[ "$volume" == "$newest" ]]; then
            :
        elif [[ -n "$(overlays_of "$(volume_path "$volume")")" ]]; then
            log "old base volume $volume kept: labs still use it"
        else
            delete_base "$volume"
            log "old base volume $volume deleted (newer $newest installed)"
        fi
    done
}

gc_all_bases() {
    local image
    virsh_lab vol-list --pool "$LAB_POOL" | awk 'NR > 2 && NF && $1 !~ /^ostyr-/ {print $1}' |
        sed -n -E 's/^(.+)-[0-9a-f]{12}\.qcow2$/\1/p' | sort -u | while read -r image; do
        gc_bases "$image"
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
