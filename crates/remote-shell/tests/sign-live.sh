#!/usr/bin/env bash
# Usage: crates/remote-shell/tests/sign-live.sh <lab-state-dir>
# Live proof of the OpenShell signer on a datastore-pair lab: a scratch database, the signer example, agent-command's own verifier, and the attacks.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: sign-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
musl="$here/target/x86_64-unknown-linux-musl/release/examples"
database="rshell_sign_$$"
work="/tmp/rshell-sign-$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }

owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true' EXIT
ssh -n "${ssh_options[@]}" "$client_user@$client_address" "mkdir -p $work"
for binary in rshell_sign rshell_register shell_record command_tool; do
    scp "${ssh_options[@]}" "$musl/$binary" "$client_user@$client_address:$work/$binary"
done
scp "${ssh_options[@]}" "$here/crates/remote-shell/tests/sign-live-remote.sh" "$client_user@$client_address:$work/sign-live-remote.sh"
ssh -n "${ssh_options[@]}" "$client_user@$client_address" "WORK=$work DATABASE=$database bash $work/sign-live-remote.sh"
