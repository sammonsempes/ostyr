#!/usr/bin/env bash
# Usage: lab/tests/store-lock-proof.sh <task-id>
# Copies module_api and auth_tool (built from the working tree) to the VM of an ubuntu-single lab and runs store-lock-remote.sh there.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

task_id="${1:?usage: store-lock-proof.sh <task-id>}"
lab_state="$(state_dir "$task_id")"
read -r _ vm_user vm_address < <(head -n 1 "$lab_state/vms.txt")
[[ -n "$vm_address" ]] || die "no VM in $lab_state/vms.txt"
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

cargo build --examples -p core-api -p core-auth
ssh -n "${ssh_options[@]}" "$vm_user@$vm_address" "sudo apt-get install -y jq >/dev/null 2>&1 || true; rm -rf /tmp/store-proof && mkdir /tmp/store-proof"
scp "${ssh_options[@]}" "$REPO_DIR/target/debug/examples/module_api" "$REPO_DIR/target/debug/examples/auth_tool" \
    "$LAB_DIR/tests/fixtures/stored-passkey.json" "$LAB_DIR/tests/store-lock-remote.sh" "$vm_user@$vm_address:/tmp/store-proof/"
ssh -n "${ssh_options[@]}" "$vm_user@$vm_address" "bash /tmp/store-proof/store-lock-remote.sh /tmp/store-proof"
