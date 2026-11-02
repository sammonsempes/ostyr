#!/usr/bin/env bash
# Usage: lab/images/build.sh <image>
# Builds lab/images/<image>.pkr.hcl with Packer (QEMU, checksum-verified official media) and uploads it as base volume <image>.qcow2.
# The previous volume is replaced only when no overlay depends on it. The build date is recorded in volume <image>.qcow2.built.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

image="${1:?usage: build.sh <image>}"
[[ "$image" =~ ^[a-z0-9-]+$ ]] || die "invalid image name '$image'"
template="$LAB_DIR/images/$image.pkr.hcl"
[[ -f "$template" ]] || die "no template $template"
volume="$image.qcow2"
stamp_volume="$volume.built"

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

upload_volume() {
    local name="$1" file="$2" format="$3"
    local size_bytes
    size_bytes="$(stat -c %s "$file")"
    virsh_lab vol-create-as "$LAB_POOL" "$name" "$size_bytes" --format "$format" >/dev/null
    virsh_lab vol-upload --pool "$LAB_POOL" "$name" "$file"
}

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

ssh-keygen -q -t ed25519 -N '' -C "ostyr-packer-$image" -f "$work_dir/id_ed25519"
packer init "$template"
packer build -color=false \
    -var "output_directory=$work_dir/output" \
    -var "ssh_private_key_file=$work_dir/id_ed25519" \
    -var "ssh_public_key=$(cat "$work_dir/id_ed25519.pub")" \
    "$template"
built="$work_dir/output/$volume"
[[ -f "$built" ]] || die "packer produced no $built"
qemu-img check "$built" >/dev/null
date +%s >"$work_dir/built"

ensure_pool
if virsh_lab vol-info --pool "$LAB_POOL" "$volume" >/dev/null 2>&1; then
    dependants="$(overlays_of "$(volume_path "$volume")")"
    [[ -z "$dependants" ]] || die "base volume $volume is in use by: $(tr '\n' ' ' <<<"$dependants"); the previous image is kept, run lab/down.sh for those labs and rebuild"
    virsh_lab vol-delete --pool "$LAB_POOL" "$volume" >/dev/null
fi
if virsh_lab vol-info --pool "$LAB_POOL" "$stamp_volume" >/dev/null 2>&1; then
    virsh_lab vol-delete --pool "$LAB_POOL" "$stamp_volume" >/dev/null
fi
upload_volume "$volume" "$built" qcow2
upload_volume "$stamp_volume" "$work_dir/built" raw
log "base volume $volume uploaded, built $(date -d "@$(cat "$work_dir/built")" --iso-8601=seconds)"
