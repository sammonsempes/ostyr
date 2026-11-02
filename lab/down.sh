#!/usr/bin/env bash
# Usage: lab/down.sh <task-id>
# Destroys the domains, overlays, network and state of one task's lab. Idempotent.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

task_id="${1:?usage: down.sh <task-id>}"
validate_task_id "$task_id"

prefix="$(lab_prefix "$task_id")"
lab_state="$(state_dir "$task_id")"

if [[ -f "$lab_state/lab.tfstate" && -f "$lab_state/vars.json" ]]; then
    run_tofu "$task_id" destroy -input=false -auto-approve -no-color -state="$lab_state/lab.tfstate" -var-file="$lab_state/vars.json" ||
        log "destroy through state failed, sweeping by name"
fi

virsh_lab list --all --name | names_with_prefix "$prefix-" | while read -r domain; do
    virsh_lab destroy "$domain" >/dev/null 2>&1 || log "domain $domain was not running"
    virsh_lab undefine --nvram "$domain" >/dev/null
done

if virsh_lab pool-info "$LAB_POOL" >/dev/null 2>&1; then
    virsh_lab vol-list --pool "$LAB_POOL" | awk 'NR > 2 && $1 != "" {print $1}' | names_with_prefix "$prefix-" | while read -r volume; do
        virsh_lab vol-delete --pool "$LAB_POOL" "$volume" >/dev/null
    done
fi

virsh_lab net-list --all --name | awk -v n="$prefix" '$0 == n' | while read -r network; do
    virsh_lab net-destroy "$network" >/dev/null 2>&1 || log "network $network was not active"
    virsh_lab net-undefine "$network" >/dev/null
done

rm -rf "$lab_state"
log "lab $task_id destroyed"
