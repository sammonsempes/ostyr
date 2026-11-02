#!/usr/bin/env bash
# Usage: lab/base-ubuntu.sh <volume-name>
# Downloads the official Ubuntu 24.04 cloud image, verifies its SHA-256 against the published sums, and uploads it as a base volume.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

readonly IMAGE_BASE_URL="https://cloud-images.ubuntu.com/noble/current"
readonly IMAGE_FILE="noble-server-cloudimg-amd64.img"

volume_name="${1:?usage: base-ubuntu.sh <volume-name>}"

ensure_pool
if virsh_lab vol-info --pool "$LAB_POOL" "$volume_name" >/dev/null 2>&1; then
    log "base volume $volume_name already present"
    exit 0
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

log "downloading $IMAGE_FILE"
curl -fsSL --proto '=https' -o "$work_dir/$IMAGE_FILE" "$IMAGE_BASE_URL/$IMAGE_FILE"
curl -fsSL --proto '=https' -o "$work_dir/SHA256SUMS" "$IMAGE_BASE_URL/SHA256SUMS"
(cd "$work_dir" && grep -F " *$IMAGE_FILE" SHA256SUMS | sha256sum -c -) || die "checksum mismatch for $IMAGE_FILE"

qemu-img convert -O qcow2 "$work_dir/$IMAGE_FILE" "$work_dir/$volume_name"
size_bytes="$(stat -c %s "$work_dir/$volume_name")"
virsh_lab vol-create-as "$LAB_POOL" "$volume_name" "$size_bytes" --format qcow2 >/dev/null
virsh_lab vol-upload --pool "$LAB_POOL" "$volume_name" "$work_dir/$volume_name"
log "base volume $volume_name uploaded"
