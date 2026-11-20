#!/usr/bin/env bash
set -euo pipefail
MOUNT_POINT=/run/ostyr-gate
SIZE="${GATE_TMPFS_SIZE:-32G}"
UNIT_DIR="${GATE_TMPFS_UNIT_DIR:-/etc/systemd/system}"
if [ "$(id -u)" != 0 ]; then
  echo "gate-tmpfs: run as root" >&2
  exit 1
fi
UNIT=$(systemd-escape -p --suffix=mount "$MOUNT_POINT")
cat >"$UNIT_DIR/$UNIT.new" <<EOF
[Unit]
Description=Ostyr pre-commit gate scratch (tmpfs)

[Mount]
What=tmpfs
Where=$MOUNT_POINT
Type=tmpfs
Options=mode=1777,size=$SIZE,nosuid,nodev

[Install]
WantedBy=local-fs.target
EOF
mv "$UNIT_DIR/$UNIT.new" "$UNIT_DIR/$UNIT"
systemctl daemon-reload
systemctl enable "$UNIT"
systemctl restart "$UNIT"
findmnt -n -o FSTYPE,SIZE,OPTIONS "$MOUNT_POINT"
