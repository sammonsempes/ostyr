#!/usr/bin/env bash
set -euo pipefail
OWNER=$1
CHECKOUT=$2
HOME_DIR=$3
HOME_MODE=$(stat -c %a "$HOME_DIR")
TREES=("$CHECKOUT" "$HOME_DIR/.rustup" "$HOME_DIR/.cargo")
restore() {
  chmod "$HOME_MODE" "$HOME_DIR"
  chown -R "$OWNER:$(id -gn "$OWNER")" "${TREES[@]}"
  chown "$OWNER:$(id -gn "$OWNER")" "$HOME_DIR"
}
trap restore EXIT
chown -R root:root "${TREES[@]}"
chown root:root "$HOME_DIR"
chmod o+x "$HOME_DIR"
cd "$CHECKOUT"
.githooks/pre-commit
