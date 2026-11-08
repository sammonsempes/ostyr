#!/usr/bin/env bash
# Usage: lab/images/build.sh [--force] <image>   (LAB_FORCE_BUILD=1 is the same as --force)
# Builds lab/images/<image>.pkr.hcl with Packer (QEMU, checksum-verified official media) and uploads it as base volume <image>.qcow2.
# The previous volume is replaced only when no overlay depends on it. The build date is recorded in volume <image>.qcow2.built.
# The fingerprint of the build inputs is recorded in volume <image>.qcow2.inputs; when it matches and the volume exists, nothing is rebuilt.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

force="${LAB_FORCE_BUILD:-0}"
if [[ "${1:-}" == "--force" ]]; then
    force=1
    shift
fi
image="${1:?usage: build.sh [--force] <image>}"
[[ "$image" =~ ^[a-z0-9-]+$ ]] || die "invalid image name '$image'"
template="$LAB_DIR/images/$image.pkr.hcl"
[[ -f "$template" ]] || die "no template $template"
volume="$image.qcow2"
stamp_volume="$volume.built"
inputs_volume="$volume.inputs"
LAB_BUILD_LOCK_DIR="${LAB_BUILD_LOCK_DIR:-$HOME/.cache/ostyr-lab/build-locks}"
UBUNTU_CLOUDIMAGE_KEYRING="${UBUNTU_CLOUDIMAGE_KEYRING:-/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg}"

upload_volume() {
    local name="$1" file="$2" format="$3"
    local size_bytes
    size_bytes="$(stat -c %s "$file")"
    virsh_lab vol-create-as "$LAB_POOL" "$name" "$size_bytes" --format "$format" >/dev/null
    virsh_lab vol-upload --pool "$LAB_POOL" "$name" "$file"
}

inputs_fingerprint() {
    local files=("$image.pkr.hcl")
    case "$image" in
        win11|ws2022-dc) files+=(pins.tsv windows) ;;
        rocky-*) files+=("keys/$image.asc") ;;
    esac
    [[ ! -d "$LAB_DIR/images/$image" ]] || files+=("$image")
    (cd "$LAB_DIR/images" && find "${files[@]}" -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
}

work_dir="$(mktemp -d)"
trap 'chmod -R u+w "$work_dir" 2>/dev/null; rm -rf "$work_dir"' EXIT

mkdir -p "$LAB_BUILD_LOCK_DIR"
exec 9>"$LAB_BUILD_LOCK_DIR/$image.lock"
if ! flock -n 9; then
    log "waiting for another build of $image"
    flock 9
fi

ensure_pool
inputs="$(inputs_fingerprint)"
if [[ "$force" != "1" ]] && virsh_lab vol-info --pool "$LAB_POOL" "$volume" >/dev/null 2>&1 &&
    virsh_lab vol-download --pool "$LAB_POOL" "$inputs_volume" "$work_dir/stored-inputs" >/dev/null 2>&1 &&
    [[ "$(cat "$work_dir/stored-inputs")" == "$inputs" ]]; then
    log "$image up to date (inputs $inputs), use --force to rebuild"
    exit 0
fi

ssh-keygen -q -t ed25519 -N '' -C "ostyr-packer-$image" -f "$work_dir/id_ed25519"

source "$LAB_DIR/images/iso-cache.sh"

prepare_windows() {
    local iso_name="$1"
    local virtio_iso
    iso_path="$(fetch_pinned "$iso_name")"
    virtio_iso="$(fetch_pinned virtio-win)"
    cloudbase_msi="$(fetch_pinned cloudbase-init)"
    mkdir -p "$work_dir/drivers"
    xorriso -osirrox on -indev "$virtio_iso" -extract /viostor "$work_dir/drivers/viostor" -extract /NetKVM "$work_dir/drivers/NetKVM" >"$work_dir/xorriso.log" 2>&1 ||
        die "cannot extract the virtio drivers from $virtio_iso"
    chmod -R u+rwX "$work_dir/drivers"
    build_password="Aa1-$(openssl rand -hex 12)"
    image_sum="sha256:$(pin_field "$iso_name" 2)"
    extra_vars=(-var "iso_path=$iso_path" -var "drivers_dir=$work_dir/drivers" -var "cloudbase_msi=$cloudbase_msi" -var "build_password=$build_password")
}

prepare_linux() {
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
        ubuntu-*|zitadel|k3s-node|backup-server|attacker|datastore)
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
}

extra_vars=()
case "$image" in
    win11) prepare_windows win11 ;;
    ws2022-dc) prepare_windows ws2022 ;;
    *) prepare_linux ;;
esac

packer init "$template"
packer build -color=false \
    -var "image_checksum=$image_sum" \
    -var "output_directory=$work_dir/output" \
    -var "ssh_private_key_file=$work_dir/id_ed25519" \
    -var "ssh_public_key=$(cat "$work_dir/id_ed25519.pub")" \
    "${extra_vars[@]}" \
    "$template"
built="$work_dir/output/$volume"
[[ -f "$built" ]] || die "packer produced no $built"
qemu-img check "$built" >/dev/null
date +%s >"$work_dir/built"
printf '%s\n' "$inputs" >"$work_dir/inputs"

ensure_pool
if virsh_lab vol-info --pool "$LAB_POOL" "$volume" >/dev/null 2>&1; then
    dependants="$(overlays_of "$(volume_path "$volume")")"
    [[ -z "$dependants" ]] || die "base volume $volume is in use by: $(tr '\n' ' ' <<<"$dependants"); the previous image is kept, run lab/down.sh for those labs and rebuild"
    virsh_lab vol-delete --pool "$LAB_POOL" "$volume" >/dev/null
fi
if virsh_lab vol-info --pool "$LAB_POOL" "$stamp_volume" >/dev/null 2>&1; then
    virsh_lab vol-delete --pool "$LAB_POOL" "$stamp_volume" >/dev/null
fi
if virsh_lab vol-info --pool "$LAB_POOL" "$inputs_volume" >/dev/null 2>&1; then
    virsh_lab vol-delete --pool "$LAB_POOL" "$inputs_volume" >/dev/null
fi
upload_volume "$volume" "$built" qcow2
upload_volume "$inputs_volume" "$work_dir/inputs" raw
upload_volume "$stamp_volume" "$work_dir/built" raw
log "base volume $volume uploaded, built $(date -d "@$(cat "$work_dir/built")" --iso-8601=seconds)"
