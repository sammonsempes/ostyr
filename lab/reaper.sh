#!/usr/bin/env bash
# Usage: lab/reaper.sh
# Destroys, through down.sh, every lab whose domains were created more than LAB_VM_TTL_MINUTES (default 120) ago. Reads the creation time in domain metadata.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

readonly SECONDS_PER_MINUTE=60
readonly DEFAULT_TTL_MINUTES=120

ttl_minutes="${LAB_VM_TTL_MINUTES:-$DEFAULT_TTL_MINUTES}"
[[ "$ttl_minutes" =~ ^[0-9]+$ ]] || die "invalid LAB_VM_TTL_MINUTES '$ttl_minutes'"
now="$(date +%s)"

metadata_field() {
    local domain="$1" field="$2"
    virsh_lab metadata "$domain" --uri urn:ostyr:lab 2>/dev/null | tr -d '\n' | sed -n "s/.*$field>\([^<][^<]*\)<.*/\1/p"
}

expired_tasks() {
    local domain created task
    virsh_lab list --all --name | names_with_prefix "ostyr-" | while read -r domain; do
        created="$(metadata_field "$domain" created || true)"
        task="$(metadata_field "$domain" task || true)"
        if [[ "$created" =~ ^[0-9]+$ && "$task" =~ ^[A-Za-z0-9]+$ && "$domain" == "$(lab_prefix "$task")-"* ]] &&
            ((now - created > ttl_minutes * SECONDS_PER_MINUTE)); then
            printf '%s\n' "$task"
        fi
    done | sort -u
}

while read -r task; do
    log "reaper: lab $task is older than $ttl_minutes minutes, destroying"
    LAB_REAPER_ACTIVE=1 "$LAB_DIR/down.sh" "$task" || log "reaper: destroying $task failed"
done < <(expired_tasks)
