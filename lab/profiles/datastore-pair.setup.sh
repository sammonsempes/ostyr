#!/usr/bin/env bash
# Usage: lab/profiles/datastore-pair.setup.sh <lab-state-dir> <lab-prefix>
# Run by up.sh once both VMs answer SSH: adds /etc/hosts entries on both, provisions the datastore VM, then installs the lab CA, the nats CLI
# and the PostgreSQL client packages (baked in the datastore image) on the client VM.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly DATASTORE_DOMAIN="datastore.lab.test"
readonly CLIENT_DOMAIN="client.lab.test"
readonly CLIENT_DIR="/usr/local/share/ostyr-lab/client"

lab_state="${1:?usage: datastore-pair.setup.sh <lab-state-dir> <lab-prefix>}"
key="$lab_state/id_ed25519"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || die "vms.txt lacks the datastore and client VMs"

ssh_options=(-i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
hosts_entries="$datastore_address $DATASTORE_DOMAIN
$client_address $CLIENT_DOMAIN"
for target in "$datastore_user@$datastore_address" "$client_user@$client_address"; do
    ssh -n "${ssh_options[@]}" "$target" "printf '%s\n' '$hosts_entries' | sudo tee -a /etc/hosts >/dev/null"
done

ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "sudo /usr/local/sbin/ostyr-datastore-provision '$DATASTORE_DOMAIN' '$datastore_address'" ||
    die "ostyr-datastore-provision failed on the datastore VM (see: journalctl on $datastore_address)"
for provisioned in /etc/ostyr-lab/s3-access-key /etc/ostyr-lab/s3-secret-key; do
    ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "sudo test -s $provisioned" ||
        die "$provisioned is missing after provisioning: the datastore base image predates Garage (run lab/images/build.sh datastore) or the Garage step failed"
done

transfer_dir="$lab_state/client-files"
mkdir -p "$transfer_dir"
ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "cat /etc/ostyr-lab/ca.pem" >"$transfer_dir/ca.pem"
ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "sudo tar -C $CLIENT_DIR -cf - ." >"$transfer_dir/client.tar"
ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "sudo cat /etc/ostyr-lab/datastore.env" >"$transfer_dir/datastore.env"
ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "sudo cat /etc/ostyr-lab/s3-access-key" >"$transfer_dir/s3-access-key"
ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "sudo cat /etc/ostyr-lab/s3-secret-key" >"$transfer_dir/s3-secret-key"
chmod 600 "$transfer_dir/datastore.env" "$transfer_dir/s3-access-key" "$transfer_dir/s3-secret-key"
scp "${ssh_options[@]}" "$transfer_dir/ca.pem" "$transfer_dir/client.tar" "$transfer_dir/datastore.env" "$transfer_dir/s3-access-key" "$transfer_dir/s3-secret-key" "$client_user@$client_address:/tmp/"
ssh -n "${ssh_options[@]}" "$client_user@$client_address" "set -e
sudo install -d -m 755 /etc/ostyr-lab /tmp/client-pkgs
sudo install -m 644 /tmp/ca.pem /etc/ostyr-lab/ca.pem
sudo install -m 600 /tmp/datastore.env /etc/ostyr-lab/datastore.env
sudo install -m 600 /tmp/s3-access-key /etc/ostyr-lab/s3-access-key
sudo install -m 600 /tmp/s3-secret-key /etc/ostyr-lab/s3-secret-key
sudo install -m 644 /tmp/ca.pem /usr/local/share/ca-certificates/ostyr-lab.crt
sudo update-ca-certificates >/dev/null
sudo tar -C /tmp/client-pkgs -xf /tmp/client.tar
sudo install -m 755 /tmp/client-pkgs/nats /usr/local/bin/nats
sudo dpkg -i /tmp/client-pkgs/libpq5_*.deb /tmp/client-pkgs/postgresql-client-common_*.deb /tmp/client-pkgs/postgresql-client-16_*.deb >/dev/null
sudo rm -rf /tmp/client-pkgs /tmp/client.tar /tmp/ca.pem /tmp/datastore.env /tmp/s3-access-key /tmp/s3-secret-key"
rm -rf "$transfer_dir"
