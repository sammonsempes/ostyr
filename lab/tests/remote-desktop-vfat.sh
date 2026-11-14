#!/usr/bin/env bash
# Usage: lab/tests/remote-desktop-vfat.sh <task-id>
# Builds relay_token, copies it to the VM of an ubuntu-single lab and checks that keygen refuses a seed file on vfat reached through a symlink.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

task_id="${1:?usage: remote-desktop-vfat.sh <task-id>}"
lab_state="$(state_dir "$task_id")"
read -r _ vm_user vm_address < <(head -n 1 "$lab_state/vms.txt")
[[ -n "$vm_address" ]] || die "no VM in $lab_state/vms.txt"
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

cargo build --example relay_token -p remote-desktop
scp "${ssh_options[@]}" "$REPO_DIR/target/debug/examples/relay_token" "$vm_user@$vm_address:/tmp/relay_token"
ssh "${ssh_options[@]}" "$vm_user@$vm_address" "sudo bash -s" <<'REMOTE'
set -euo pipefail
work=/tmp/vfat-proof
umount "$work/mnt" 2>/dev/null || true
rm -rf "$work"
mkdir -p "$work/mnt" "$work/links"
truncate -s 8M "$work/disk.img"
mkfs.vfat "$work/disk.img" >/dev/null
mount -o loop,uid=65534,gid=65534,umask=022 "$work/disk.img" "$work/mnt"
ln -s "$work/mnt" "$work/links/vfat"
chown -h 65534:65534 "$work/links/vfat"
if /tmp/relay_token keygen "$work/links/vfat/seed" "$work/public"; then
    echo "FAIL keygen accepted a seed file on vfat"
    exit 1
fi
size="$(stat -c %s "$work/mnt/seed")"
[[ "$size" == 0 ]] || { echo "FAIL seed file holds $size bytes"; exit 1; }
umount "$work/mnt"
echo "ok keygen refused on vfat and the seed file is 0 bytes"
REMOTE
