#!/usr/bin/env bash
# Usage: crates/remote-shell/tests/routes-live.sh <lab-state-dir>
# Live check of the register routes on a datastore-pair lab: rshell_register fills a scratch database, two rshell_api instances (tenants a and b) serve it on the
# client VM, curl reads it back, and the PostgreSQL log (log_connections = on) proves that a refused request opens no connection.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: routes-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
musl="$here/target/x86_64-unknown-linux-musl/release/examples"
database="rshell_live_$$"
work="/tmp/rshell-live-$$"
port_base=$((20000 + $$ % 20000))
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
client_phase() { ssh -n "${ssh_options[@]}" "$client_user@$client_address" "WORK=$work DATABASE=$database PORT_BASE=$port_base bash $work/routes-live-remote.sh $1"; }
connections() { datastore_ssh "sudo grep -c 'connection authorized.*database=$database' /var/log/postgresql/postgresql-16-main.log || true"; }

owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true' EXIT
datastore_ssh "sudo -u postgres psql -Atc \"ALTER SYSTEM SET log_connections = on\" -c 'SELECT pg_reload_conf()'"
ssh -n "${ssh_options[@]}" "$client_user@$client_address" "mkdir -p $work"
for binary in rshell_register rshell_api shell_record; do scp "${ssh_options[@]}" "$musl/$binary" "$client_user@$client_address:$work/$binary"; done
scp "${ssh_options[@]}" "$musl/../ostyr-auth" "$client_user@$client_address:$work/ostyr-auth"
scp "${ssh_options[@]}" "$here/crates/remote-shell/tests/routes-live-remote.sh" "$client_user@$client_address:$work/routes-live-remote.sh"

client_phase setup
before="$(connections)"
client_phase refused
after_refused="$(connections)"
echo "connections opened by the refused requests: $((after_refused - before))"
client_phase good
after_good="$(connections)"
echo "connections opened by the three good requests: $((after_good - after_refused))"
client_phase attacks
