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
UBUNTU_CLOUDIMAGE_KEYRING="${UBUNTU_CLOUDIMAGE_KEYRING:-/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg}"

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

base_url="$(sed -n '/variable "image_base_url"/,/}/ s/^ *default *= *"\(.*\)"/\1/p' "$template")"
image_file="$(sed -n 's/^ *iso_url *= *"\${var.image_base_url}\/\(.*\)"/\1/p' "$template")"
[[ -n "$base_url" && -n "$image_file" ]] || die "cannot read image_base_url and iso_url from $template"
fetch() {
    curl --fail --silent --show-error --location --output "$2" "$1"
}

verify_rocky() {
    local key="$1" sums_name="$2" sig_name="$3"
    fetch "$base_url/$sums_name" "$work_dir/sums"
    fetch "$base_url/$sig_name" "$work_dir/sums.sig"
    gpg --dearmor <"$LAB_DIR/images/keys/$key.asc" >"$work_dir/key.gpg"
    gpgv --keyring "$work_dir/key.gpg" "$work_dir/sums.sig" "$work_dir/sums" || die "checksum signature check failed"
    image_sum="sha256:$(sed -n "s/^SHA256 ($image_file) = \([0-9a-f]\{64\}\)\$/\1/p" "$work_dir/sums")"
}

case "$image" in
    ubuntu-*)
        fetch "$base_url/SHA256SUMS" "$work_dir/SHA256SUMS"
        fetch "$base_url/SHA256SUMS.gpg" "$work_dir/SHA256SUMS.gpg"
        gpgv --keyring "$UBUNTU_CLOUDIMAGE_KEYRING" "$work_dir/SHA256SUMS.gpg" "$work_dir/SHA256SUMS" || die "SHA256SUMS signature check failed"
        image_sum="sha256:$(awk -v file="*$image_file" '$2 == file {print $1}' "$work_dir/SHA256SUMS")"
        ;;
    rocky-9) verify_rocky rocky-9 "$image_file.CHECKSUM" "$image_file.CHECKSUM.asc" ;;
    rocky-8) verify_rocky rocky-8 CHECKSUM CHECKSUM.sig ;;
    debian-*)
        fetch "$base_url/SHA512SUMS" "$work_dir/SHA512SUMS"
        image_sum="sha512:$(awk -v file="$image_file" '$2 == file {print $1}' "$work_dir/SHA512SUMS")"
        ;;
    *) die "no checksum verification known for image '$image'" ;;
esac
[[ "$image_sum" =~ ^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$ ]] || die "no checksum for $image_file in the verified checksum file"

packer init "$template"
packer build -color=false \
    -var "image_checksum=$image_sum" \
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
