#!/usr/bin/env bash
# Usage: sudo lab/host/install.sh
# Installs, idempotently, the lab firewall (nft rule set + unit) and the reaper system unit and timer, then reloads systemd.
set -euo pipefail

HOST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly HOST_DIR
readonly LAB_ROOT="${HOST_DIR%/*}"
readonly UNIT_DIR="/etc/systemd/system"
readonly NFT_DIR="/etc/nftables.d"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "install.sh must run as root (try: sudo $0)" >&2
    exit 1
fi

install -d -m 0755 "$NFT_DIR"
install -m 0644 "$HOST_DIR/ostyr-lab.nft" "$NFT_DIR/ostyr-lab.nft"
install -m 0644 "$HOST_DIR/ostyr-lab-firewall.service" "$UNIT_DIR/ostyr-lab-firewall.service"
sed "s|^ExecStart=.*|ExecStart=$LAB_ROOT/reaper.sh|" "$LAB_ROOT/systemd/ostyr-lab-reaper.service" >"$UNIT_DIR/ostyr-lab-reaper.service"
install -m 0644 "$LAB_ROOT/systemd/ostyr-lab-reaper.timer" "$UNIT_DIR/ostyr-lab-reaper.timer"
chmod 0644 "$UNIT_DIR/ostyr-lab-reaper.service"

systemctl daemon-reload
systemctl enable ostyr-lab-firewall.service ostyr-lab-reaper.timer
systemctl restart ostyr-lab-firewall.service
systemctl start ostyr-lab-reaper.timer
