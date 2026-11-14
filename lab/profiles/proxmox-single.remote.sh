#!/usr/bin/env bash
# Usage (as root, on the VM): proxmox-single.remote.sh <address> <key-sha512>   (key at /tmp/proxmox-release-bookworm.gpg)
# Installs Proxmox VE 8 from the no-subscription repository on Debian 12, creates two API tokens and three guest definitions.
# Idempotent: each step checks its own result first.
set -euo pipefail

readonly KEY_PATH="/etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg"
readonly NODE="pve"
readonly TEMPLATE_PATTERN="debian-12-standard"
readonly API_ATTEMPTS=60
readonly CLOUD_INIT_WAIT_SECONDS=1800

address="${1:?usage: proxmox-single.remote.sh <address> <key-sha512>}"
digest="${2:?usage: proxmox-single.remote.sh <address> <key-sha512>}"
export DEBIAN_FRONTEND=noninteractive

echo "$digest  /tmp/proxmox-release-bookworm.gpg" | sha512sum --check --status || { echo "key digest mismatch" >&2; exit 1; }

if ! dpkg-query -W -f='${Status}' proxmox-ve 2>/dev/null | grep -q 'install ok installed'; then
    timeout "$CLOUD_INIT_WAIT_SECONDS" cloud-init status --wait || { echo "cloud-init did not finish within ${CLOUD_INIT_WAIT_SECONDS}s" >&2; exit 1; }
    install -m 0644 /tmp/proxmox-release-bookworm.gpg "$KEY_PATH"
    echo "deb [arch=amd64] http://download.proxmox.com/debian/pve bookworm pve-no-subscription" >/etc/apt/sources.list.d/pve-install-repo.list
    hostnamectl set-hostname "$NODE"
    printf 'preserve_hostname: true\nmanage_etc_hosts: false\n' >/etc/cloud/cloud.cfg.d/99-pve.cfg
    sed -i '/^127\.0\.1\.1/d' /etc/hosts
    grep -q " $NODE\$" /etc/hosts || echo "$address $NODE.lab.test $NODE" >>/etc/hosts
    echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
    apt-get -o DPkg::Lock::Timeout=600 update
    apt-get -o DPkg::Lock::Timeout=600 install -y proxmox-ve postfix open-iscsi chrony
fi
systemctl enable --now pve-cluster pvedaemon pveproxy pvestatd >/dev/null

wait_for_api() {
    local i
    for ((i = 0; i < API_ATTEMPTS; i++)); do
        pvesh get /version >/dev/null 2>&1 && return 0
        sleep 5
    done
    return 1
}
wait_for_api || { echo "Proxmox API did not answer" >&2; exit 1; }

make_token() {
    local user="$1" role="$2" file="$3" secret
    pveum user list --output-format json | grep -q "\"userid\":\"$user@pve\"" || pveum user add "$user@pve"
    pveum acl modify / --users "$user@pve" --roles "$role"
    if ! pveum user token list "$user@pve" --output-format json | grep -q '"tokenid":"lab"'; then
        secret="$(pveum user token add "$user@pve" lab --privsep 0 --output-format json | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')"
        [[ -n "$secret" ]] || { echo "token creation for $user returned no secret" >&2; exit 1; }
        install -m 0600 /dev/null "$file"
        echo "$user@pve!lab=$secret" >"$file"
    fi
}
make_token lab-auditor PVEAuditor /root/pve-auditor-token
make_token lab-admin PVEVMAdmin /root/pve-admin-token

for vmid in 9001 9002; do
    qm status "$vmid" >/dev/null 2>&1 || qm create "$vmid" --name "lab-vm-$vmid" --memory 256 --cores 1 --kvm 0 --ostype l26
done
if ! pct status 9003 >/dev/null 2>&1; then
    set -a
    source /etc/environment
    set +a
    [[ -z "${http_proxy:-}" ]] || pvesh set /cluster/options --http_proxy "$http_proxy"
    pveam update || echo "pveam update failed" >&2
    template="$(pveam available --section system | awk -v p="$TEMPLATE_PATTERN" '$2 ~ p {print $2}' | tail -n 1)"
    if [[ -n "$template" ]] && { pveam download local "$template" || true; } && pveam list local | grep -q "$template"; then
        pct create 9003 "local:vztmpl/$template" --hostname lab-ct --memory 256 --rootfs local:2
    else
        echo "LXC template unavailable through the proxy: two VM definitions only" >&2
    fi
fi
echo "setup done"
