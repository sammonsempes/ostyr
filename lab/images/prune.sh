#!/usr/bin/env bash
# Usage: lab/images/prune.sh
# Deletes base volumes (and their .built and .inputs stamps) that no profile references and no overlay depends on. Lab volumes (ostyr-*) are never touched.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

referenced="$(cat "$LAB_DIR"/profiles/*.yaml | awk '$1 == "base_image:" || $2 == "base_image:" {print $NF}')"

virsh_lab vol-list --pool "$LAB_POOL" | awk 'NR > 2 && NF && $1 !~ /^ostyr-/ && $1 ~ /\.qcow2$/ {print $1}' | while read -r volume; do
    stem="$(sed -E 's/-[0-9a-f]{12}\.qcow2$/.qcow2/' <<<"$volume")"
    if grep -qxF "$stem" <<<"$referenced"; then
        log "keep $volume (referenced by a profile)"
    elif [[ -n "$(overlays_of "$(volume_path "$volume")")" ]]; then
        log "keep $volume (an overlay depends on it)"
    else
        delete_base "$volume"
        log "deleted $volume"
    fi
done
