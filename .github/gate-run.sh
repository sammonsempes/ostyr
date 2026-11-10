#!/usr/bin/env bash
set -euo pipefail
OWNER=$1
CHECKOUT=$2
HOME_DIR=$3
MAX_DEPTH=64
HOME_MODE=$(stat -c %a "$HOME_DIR")
TREES=("$CHECKOUT" "$HOME_DIR/.rustup" "$HOME_DIR/.cargo")
ANCESTORS=()
ANCESTOR_MODES=()
CURRENT=$(dirname "$CHECKOUT")
for _ in $(seq "$MAX_DEPTH"); do
  if [ "$CURRENT" != "$HOME_DIR" ] && [ "$CURRENT" != / ]; then
    ANCESTORS+=("$CURRENT")
    ANCESTOR_MODES+=("$(stat -c %a "$CURRENT")")
    CURRENT=$(dirname "$CURRENT")
  fi
done
GROUP=$(id -gn "$OWNER")
restore() {
  chmod "$HOME_MODE" "$HOME_DIR"
  chown -R "$OWNER:$GROUP" "${TREES[@]}"
  for index in "${!ANCESTORS[@]}"; do
    chown "$OWNER:$GROUP" "${ANCESTORS[$index]}"
    chmod "${ANCESTOR_MODES[$index]}" "${ANCESTORS[$index]}"
  done
  chown "$OWNER:$GROUP" "$HOME_DIR"
}
trap restore EXIT
chown -R root:root "${TREES[@]}"
for ancestor in "${ANCESTORS[@]}"; do
  chown root:root "$ancestor"
  chmod o+x "$ancestor"
done
chown root:root "$HOME_DIR"
chmod o+x "$HOME_DIR"
cd "$CHECKOUT"
.githooks/pre-commit
