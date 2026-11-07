#!/usr/bin/env bash
# Usage: lab/images/prune.sh
# Deletes base volumes (and their .built and .inputs stamps) that no profile references and no overlay depends on. Lab volumes (ostyr-*) are never touched.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

referenced="$(cat "$LAB_DIR"/profiles/*.yaml | awk '$1 == "base_image:" || $2 == "base_image:" {print $NF}')"

virsh_lab vol-list --pool "$LAB_POOL" | awk 'NR > 2 && NF && $1 !~ /^ostyr-/ && $1 ~ /\.qcow2$/ {print $1}' | while read -r volume; do
    if grep -qxF "$volume" <<<"$referenced"; then
        log "keep $volume (referenced by a profile)"
    elif [[ -n "$(overlays_of "$(volume_path "$volume")")" ]]; then
        log "keep $volume (an overlay depends on it)"
    else
        virsh_lab vol-delete --pool "$LAB_POOL" "$volume" >/dev/null
        for suffix in built inputs; do
            virsh_lab vol-info --pool "$LAB_POOL" "$volume.$suffix" >/dev/null 2>&1 && virsh_lab vol-delete --pool "$LAB_POOL" "$volume.$suffix" >/dev/null
        done
        log "deleted $volume"
    fi
done
