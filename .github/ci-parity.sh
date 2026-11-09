#!/usr/bin/env bash
set -euo pipefail
ROOT=$(git rev-parse --show-toplevel)
BRANCH=${1:-main}
CI_USER=${CI_PARITY_USER:-root}
CPUS=${CI_PARITY_CPUS:-0-3}
RUSTUP_HOME_REAL=$(realpath "${RUSTUP_HOME:-$HOME/.rustup}")
CARGO_HOME_REAL=$(realpath "${CARGO_HOME:-$HOME/.cargo}")
mkdir -p "$ROOT/target"
WORK=$(mktemp -d "$ROOT/target/ci-parity.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
[ "$CI_USER" = root ] || id "$CI_USER" >/dev/null 2>&1 || useradd --system --create-home --home-dir "/var/lib/$CI_USER" --shell /usr/sbin/nologin "$CI_USER"
chmod 755 "$WORK"
git clone --quiet --branch "$BRANCH" "$ROOT" "$WORK/src"
mkdir -p "$WORK/cargo-home"
cp -a "$CARGO_HOME_REAL/registry" "$WORK/cargo-home/registry"
chown -R "$CI_USER" "$WORK"
mkdir -p "$WORK/bin"
find "$CARGO_HOME_REAL/bin" -maxdepth 1 ! -type d ! -name sccache -exec ln -s {} "$WORK/bin/" ";"
cd "$WORK/src"
ci() {
  setpriv --reuid="$CI_USER" --regid="$CI_USER" --init-groups taskset -c "$CPUS" env -i HOME="$(getent passwd "$CI_USER" | cut -d: -f6)" USER="$CI_USER" \
    LANG=C.UTF-8 CARGO_TERM_COLOR=never RUSTUP_HOME="$RUSTUP_HOME_REAL" CARGO_HOME="$WORK/cargo-home" \
    PATH="$WORK/bin:/usr/local/bin:/usr/bin:/bin" "$@"
}
ci cargo fetch --locked
ci .githooks/pre-commit
