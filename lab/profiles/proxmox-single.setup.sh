#!/usr/bin/env bash
# Usage: lab/profiles/proxmox-single.setup.sh <lab-state-dir> <lab-prefix>
#        lab/profiles/proxmox-single.setup.sh --check-key <key-file> <digest-file>
# Run by up.sh once the VM answers SSH: checks the pinned Proxmox repository key, ships it with proxmox-single.remote.sh and runs that script as root.
# The API tokens come back to <lab-state-dir>/pve-auditor-token and pve-admin-token (mode 600).
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly KEY_FILE="$LAB_DIR/images/keys/proxmox-release-bookworm.gpg"
readonly DIGEST_FILE="$LAB_DIR/images/keys/proxmox-release-bookworm.gpg.sha512"
readonly REMOTE_SCRIPT="$LAB_DIR/profiles/proxmox-single.remote.sh"
readonly USAGE="usage: proxmox-single.setup.sh <lab-state-dir> <lab-prefix> | --check-key <key-file> <digest-file>"

check_key() {
    local key_file digest_file
    key_file="$(realpath "$1")"
    digest_file="$(realpath "$2")"
    (cd "$(dirname "$key_file")" && awk -v f="$(basename "$key_file")" '{print $1 "  " f}' "$digest_file" | sha512sum --check --status) ||
        die "key $1 does not match the pinned SHA-512 in $2"
}

if [[ "${1:-}" == "--check-key" ]]; then
    check_key "${2:?$USAGE}" "${3:?$USAGE}"
    exit 0
fi

lab_state="${1:?$USAGE}"
: "${2:?$USAGE}"
check_key "$KEY_FILE" "$DIGEST_FILE"
key="$lab_state/id_ed25519"
read -r _ user address < <(awk '$1 == "pve"' "$lab_state/vms.txt")
[[ -n "${address:-}" ]] || die "vms.txt lacks the pve VM"

ssh_options=(-i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
digest="$(awk '{print $1}' "$DIGEST_FILE")"
scp "${ssh_options[@]}" -q "$KEY_FILE" "$user@$address:/tmp/proxmox-release-bookworm.gpg"
ssh "${ssh_options[@]}" "$user@$address" "sudo bash -s -- '$address' '$digest'" <"$REMOTE_SCRIPT"
for token in auditor admin; do
    ssh -n "${ssh_options[@]}" "$user@$address" "sudo cat /root/pve-$token-token" >"$lab_state/pve-$token-token"
    chmod 600 "$lab_state/pve-$token-token"
done
log "Proxmox VE API: https://$address:8006/api2/json (tokens in $lab_state/pve-{auditor,admin}-token, format user!token=secret)"
