#!/usr/bin/env bash
# Usage: lab/profiles/oidc-pair.setup.sh <lab-state-dir> <lab-prefix>
# Run by up.sh once both VMs answer SSH: adds static /etc/hosts entries on both, provisions Zitadel, installs the lab CA on the server VM.
# OIDC_REDIRECT_URI (environment, default https://server.lab.test/api/auth/oidc/callback) is the redirect URI of the OIDC application.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly IDP_DOMAIN="zitadel.lab.test"
readonly SERVER_DOMAIN="server.lab.test"

lab_state="${1:?usage: oidc-pair.setup.sh <lab-state-dir> <lab-prefix>}"
redirect_uri="${OIDC_REDIRECT_URI:-https://$SERVER_DOMAIN/api/auth/oidc/callback}"
key="$lab_state/id_ed25519"
read -r _ server_user server_address < <(awk '$1 == "server"' "$lab_state/vms.txt")
read -r _ idp_user idp_address < <(awk '$1 == "zitadel"' "$lab_state/vms.txt")
[[ -n "$server_address" && -n "$idp_address" ]] || die "vms.txt lacks the server and zitadel VMs"

ssh_options=(-i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
hosts_entries="$idp_address $IDP_DOMAIN
$server_address $SERVER_DOMAIN"
for target in "$server_user@$server_address" "$idp_user@$idp_address"; do
    ssh -n "${ssh_options[@]}" "$target" "printf '%s\n' '$hosts_entries' | sudo tee -a /etc/hosts >/dev/null"
done

ssh -n "${ssh_options[@]}" "$idp_user@$idp_address" "sudo /usr/local/sbin/ostyr-zitadel-provision '$IDP_DOMAIN' '$idp_address' '$redirect_uri'"

ca_file="$lab_state/zitadel-ca.pem"
ssh -n "${ssh_options[@]}" "$idp_user@$idp_address" "cat /etc/ostyr-lab/ca.pem" >"$ca_file"
scp "${ssh_options[@]}" "$ca_file" "$server_user@$server_address:/tmp/ca.pem"
ssh -n "${ssh_options[@]}" "$server_user@$server_address" \
    "sudo install -d -m 755 /etc/ostyr-lab && sudo install -m 644 /tmp/ca.pem /etc/ostyr-lab/ca.pem && sudo install -m 644 /tmp/ca.pem /usr/local/share/ca-certificates/ostyr-lab.crt && sudo update-ca-certificates >/dev/null"
