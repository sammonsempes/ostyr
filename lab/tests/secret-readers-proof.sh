#!/usr/bin/env bash
# Usage: lab/tests/secret-readers-proof.sh <task-id>
# Builds auth_tool, oncall_send and oncall_link for the musl target from the working tree, copies them to the VM of an ubuntu-single lab
# and runs secret-readers-remote.sh there as the VM user.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

task_id="${1:?usage: secret-readers-proof.sh <task-id>}"
lab_state="$(state_dir "$task_id")"
read -r _ vm_user vm_address < <(head -n 1 "$lab_state/vms.txt")
[[ -n "$vm_address" ]] || die "no VM in $lab_state/vms.txt"
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

cargo build --release --target x86_64-unknown-linux-musl --example auth_tool -p core-auth
cargo build --release --target x86_64-unknown-linux-musl --example oncall_send --example oncall_link -p oncall
ssh -n "${ssh_options[@]}" "$vm_user@$vm_address" "rm -rf /tmp/secret-proof && mkdir /tmp/secret-proof"
examples="$REPO_DIR/target/x86_64-unknown-linux-musl/release/examples"
scp "${ssh_options[@]}" "$examples/auth_tool" "$examples/oncall_send" "$examples/oncall_link" \
    "$LAB_DIR/tests/secret-readers-remote.sh" "$vm_user@$vm_address:/tmp/secret-proof/"
ssh -n "${ssh_options[@]}" "$vm_user@$vm_address" "bash /tmp/secret-proof/secret-readers-remote.sh /tmp/secret-proof"
