#!/usr/bin/env bash
set -euo pipefail
ROOT=$(git rev-parse --show-toplevel)
BRANCH=${1:-main}
CI_USER=${CI_PARITY_USER:-root}
OWNER=${CI_PARITY_OWNER:-ci-parity}
FIX=${CI_PARITY_FIX:-1}
CPUS=${CI_PARITY_CPUS:-0-3}
RUSTUP_HOME_REAL=$(realpath "${RUSTUP_HOME:-$HOME/.rustup}")
CARGO_HOME_REAL=$(realpath "${CARGO_HOME:-$HOME/.cargo}")
mkdir -p "$ROOT/target"
WORK=$(mktemp -d "$ROOT/target/ci-parity.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
for account in "$OWNER" "$CI_USER"; do
  [ "$account" = root ] || id "$account" >/dev/null 2>&1 || useradd --system --create-home --home-dir "/var/lib/$account" --shell /usr/sbin/nologin "$account"
done
chmod 755 "$WORK"
mkdir -p "$WORK/bin"
find "$CARGO_HOME_REAL/bin" -maxdepth 1 ! -type d ! -name sccache -exec ln -s {} "$WORK/bin/" ";"
if [ "$CI_USER" = root ]; then
  RUNNER_HOME="$WORK/home"
  mkdir -p "$RUNNER_HOME/.cargo"
  cp -a "$RUSTUP_HOME_REAL" "$RUNNER_HOME/.rustup"
  cp -a "$CARGO_HOME_REAL/registry" "$RUNNER_HOME/.cargo/registry"
  git clone --quiet --branch "$BRANCH" "$ROOT" "$RUNNER_HOME/src"
  chown -R "$OWNER:$OWNER" "$RUNNER_HOME"
  chmod 750 "$RUNNER_HOME"
  RUNNER_ENV=(HOME="$RUNNER_HOME" LANG=C.UTF-8 CARGO_TERM_COLOR=never RUSTUP_HOME="$RUNNER_HOME/.rustup" CARGO_HOME="$RUNNER_HOME/.cargo"
    PATH="$WORK/bin:/usr/local/bin:/usr/bin:/bin")
  cd "$RUNNER_HOME/src"
  setpriv --reuid="$OWNER" --regid="$OWNER" --init-groups env -i "${RUNNER_ENV[@]}" cargo fetch --locked
  if [ "$FIX" = 1 ]; then
    taskset -c "$CPUS" env -i "${RUNNER_ENV[@]}" "$ROOT/.github/gate-run.sh" "$OWNER" "$RUNNER_HOME/src" "$RUNNER_HOME"
  else
    taskset -c "$CPUS" env -i "${RUNNER_ENV[@]}" SUDO_UID="$(id -u "$OWNER")" .githooks/pre-commit
  fi
else
  mkdir -p "$WORK/cargo-home"
  cp -a "$CARGO_HOME_REAL/registry" "$WORK/cargo-home/registry"
  git clone --quiet --branch "$BRANCH" "$ROOT" "$WORK/src"
  chown -R "$CI_USER" "$WORK"
  cd "$WORK/src"
  ci() {
    setpriv --reuid="$CI_USER" --regid="$CI_USER" --init-groups taskset -c "$CPUS" env -i HOME="$(getent passwd "$CI_USER" | cut -d: -f6)" USER="$CI_USER" \
      LANG=C.UTF-8 CARGO_TERM_COLOR=never RUSTUP_HOME="$RUSTUP_HOME_REAL" CARGO_HOME="$WORK/cargo-home" \
      PATH="$WORK/bin:/usr/local/bin:/usr/bin:/bin" "$@"
  }
  ci cargo fetch --locked
  ci .githooks/pre-commit
fi
