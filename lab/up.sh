#!/usr/bin/env bash
# Usage: lab/up.sh <task-id>
# Creates the VMs of the task's lab profile on an isolated libvirt network. LAB_PROFILE overrides the profile named in the backlog file.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

readonly GB_PER_VM=4
readonly HOST_RESERVED_GB=8
readonly KIB_PER_GB=1048576
readonly SSH_ATTEMPTS=120
readonly SSH_DELAY_SECONDS=5
readonly SUBNET_FIRST=100
readonly SUBNET_LAST=199

task_id="${1:?usage: up.sh <task-id>}"
validate_task_id "$task_id"
run_reaper

resolve_profile() {
    local profile="${LAB_PROFILE:-}"
    local backlog_file
    if [[ -z "$profile" ]]; then
        backlog_file="$(find "$REPO_DIR/backlog" -maxdepth 1 -name "$task_id-*.md" | head -n 1)"
        [[ -n "$backlog_file" ]] || die "no backlog file for $task_id"
        profile="$(sed -n "s/^- \*\*Lab profile\*\*: \`\([^\`]*\)\`.*/\1/p" "$backlog_file" | head -n 1)"
        [[ -n "$profile" ]] || die "no 'Lab profile' field in $backlog_file"
    fi
    validate_profile_name "$profile"
    [[ -f "$LAB_DIR/profiles/$profile.yaml" ]] || die "unknown profile '$profile'"
    printf '%s' "$profile"
}

max_vms() {
    local mem_kib
    if [[ -n "${LAB_MAX_VMS:-}" ]]; then
        printf '%s' "$LAB_MAX_VMS"
    else
        mem_kib="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
        printf '%s' "$(((mem_kib / KIB_PER_GB - HOST_RESERVED_GB) / GB_PER_VM))"
    fi
}

check_quota() {
    local wanted="$1"
    local running=0 limit domain
    while read -r domain; do
        running=$((running + $(domain_units "$domain")))
    done < <(virsh_lab list --state-running --name | names_with_prefix "ostyr-")
    limit="$(max_vms)"
    if ((running + wanted > limit)); then
        die "quota exceeded: $running lab VMs running + $wanted requested > LAB_MAX_VMS=$limit"
    fi
}

ensure_base_images() {
    local profile_file="$1"
    local -a images
    local image
    mapfile -t images < <(awk '$1 == "base_image:" {print $2}' "$profile_file" | sort -u)
    for image in "${images[@]}"; do
        if ! virsh_lab vol-info --pool "$LAB_POOL" "$image" >/dev/null 2>&1; then
            "$LAB_DIR/images/build.sh" "${image%.qcow2}"
        fi
        warn_if_stale "$image"
    done
}

free_subnet_octet() {
    local used candidate
    used="$({
        ip -4 route
        ip -4 -o addr
        virsh_lab net-list --all --name | awk 'NF' | while read -r network; do
            virsh_lab net-dumpxml "$network"
        done
    } | { grep -o '192\.168\.[0-9]*' || true; } | cut -d. -f3 | sort -un)"
    candidate="$(seq "$SUBNET_FIRST" "$SUBNET_LAST" | { grep -vxF "$used" || true; } | head -n 1)"
    [[ -n "$candidate" ]] || die "no free 192.168.x.0/24 subnet"
    printf '%s' "$candidate"
}

wait_for_ssh() {
    local key="$1" user="$2" address="$3"
    local attempt
    for ((attempt = 0; attempt < SSH_ATTEMPTS; attempt++)); do
        if ssh -n -i "$key" -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
            "$user@$address" "exit 0" 2>/dev/null; then
            return 0
        fi
        sleep "$SSH_DELAY_SECONDS"
    done
    die "SSH did not answer on $address"
}

profile="$(resolve_profile)"
profile_source="$LAB_DIR/profiles/$profile.yaml"
validate_profile_fields "$profile_source"
validate_profile_choices "$profile_source"
mkdir -p "$LAB_STATE_ROOT"
exec 9>"$LAB_STATE_ROOT/up.lock"
flock 9
vm_count="$(profile_units "$profile_source")"
[[ -z "$(virsh_lab net-list --all --name | awk -v n="$(lab_prefix "$task_id")" '$0 == n')" ]] || die "lab for $task_id already exists, run lab/down.sh $task_id first"
check_quota "$vm_count"

lab_state="$(state_dir "$task_id")"
mkdir -p "$lab_state"
cp "$profile_source" "$lab_state/profile.yaml"
ssh-keygen -q -t ed25519 -N '' -C "ostyr-lab-$task_id" -f "$lab_state/id_ed25519"

ensure_pool
ensure_base_images "$profile_source"

jq -n \
    --arg task_id "$task_id" \
    --arg profile_file "$lab_state/profile.yaml" \
    --arg pool "$LAB_POOL" \
    --argjson subnet_octet "$(free_subnet_octet)" \
    --arg ssh_public_key "$(cat "$lab_state/id_ed25519.pub")" \
    --argjson created_at "$(date +%s)" \
    '$ARGS.named' >"$lab_state/vars.json"

run_tofu "$task_id" init -input=false -no-color >"$lab_state/init.log" 2>&1 || {
    cat "$lab_state/init.log" >&2
    die "init failed"
}
run_tofu "$task_id" apply -input=false -auto-approve -no-color -state="$lab_state/lab.tfstate" -var-file="$lab_state/vars.json" ||
    die "apply failed; run lab/down.sh $task_id to clean up"

flock -u 9

vms="$(run_tofu "$task_id" output -raw -state="$lab_state/lab.tfstate" vms)"
printf '%s\n' "$vms" >"$lab_state/vms.txt"
while read -r name user address; do
    wait_for_ssh "$lab_state/id_ed25519" "$user" "$address"
    printf '%s  %s  ssh -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null %s@%s\n' \
        "$(lab_prefix "$task_id")-$name" "$address" "$lab_state/id_ed25519" "$user" "$address"
done <"$lab_state/vms.txt"

setup_script="$LAB_DIR/profiles/$profile.setup.sh"
if [[ -f "$setup_script" ]]; then
    "$setup_script" "$lab_state" "$(lab_prefix "$task_id")"
fi
