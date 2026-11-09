#!/usr/bin/env bash
# Usage: lab/profiles/rocky-single.setup.sh <lab-state-dir> <lab-prefix>
# Run by up.sh once the VM answers SSH: adds baseurl repos on dl.rockylinux.org (the stock mirrorlist hosts are not allowlisted by the lab proxy),
# so dnf works through the proxy. The repo ids are a lab detail: no code may assume them.
set -euo pipefail

readonly REPO_FILE="/etc/yum.repos.d/lab-baseurl.repo"
readonly RELEASE_URL="https://dl.rockylinux.org/pub/rocky/9"

lab_state="${1:?usage: rocky-single.setup.sh <lab-state-dir> <lab-prefix>}"
key="$lab_state/id_ed25519"
read -r _ user address < <(awk '$1 == "rocky"' "$lab_state/vms.txt")
[[ -n "$address" ]] || { echo "vms.txt lacks the rocky VM" >&2; exit 1; }

ssh_options=(-i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
repo_text="[lab-baseos]
name=lab BaseOS
baseurl=$RELEASE_URL/BaseOS/\$basearch/os/
gpgcheck=0
enabled=1
[lab-appstream]
name=lab AppStream
baseurl=$RELEASE_URL/AppStream/\$basearch/os/
gpgcheck=0
enabled=1"
ssh -n "${ssh_options[@]}" "$user@$address" "printf '%s\n' '$repo_text' | sudo tee $REPO_FILE >/dev/null"
