#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "${CARGO_TARGET_DIR:-$PWD/target}"
SCRATCH=$(mktemp -d -p "${CARGO_TARGET_DIR:-$PWD/target}")
mkdir -p "$SCRATCH/tmp"
export TMPDIR="$SCRATCH/tmp"
unset CARGO_TARGET_DIR
trap 'rm -rf "$SCRATCH"' EXIT
export HOME="$SCRATCH/home"
mkdir -p "$HOME" "$SCRATCH/bin" "$SCRATCH/sync" "$SCRATCH/ram"
cat >"$SCRATCH/bin/cargo" <<'S'
#!/usr/bin/env bash
if [ "$1" = "+nightly" ] && [ "$2" = "llvm-cov" ]; then
  echo "scratch=$TMPDIR" >>"$STUB_LOG"
  if [ -n "${SYNC:-}" ]; then
    MAX_POLLS=600
    wait_for() {
      local polls=0
      while [ ! -e "$1" ] && [ "$polls" -lt "$MAX_POLLS" ]; do
        sleep 0.1
        polls=$((polls + 1))
      done
      [ -e "$1" ]
    }
    touch "$TMPDIR/held"
    if mkdir "$SYNC/role.a" 2>/dev/null; then
      touch "$SYNC/a.started"
      wait_for "$SYNC/b.started"
    else
      touch "$SYNC/b.started"
      wait_for "$SYNC/a.done"
      if [ -e "$TMPDIR/held" ]; then touch "$SYNC/b.kept"; fi
    fi
  fi
fi
S
chmod +x "$SCRATCH/bin/cargo"
export STUB_LOG="$SCRATCH/log"
R="$SCRATCH/repo"
mkdir -p "$R"
cd "$R"
git init -q
echo x >f.rs
git add -A
FAILS=0
HOOK_ENV=(env -u COVERAGE_EXPORT -u CARGO_TARGET_DIR PATH="$SCRATCH/bin:/usr/bin:/bin")

: >"$STUB_LOG"
"${HOOK_ENV[@]}" GATE_TMPFS="$SCRATCH/ram" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "scratch=$SCRATCH/ram/run-" "$STUB_LOG"; then
  echo "FAIL: scratch not on the tmpfs when it has room"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi
if [ -n "$(ls -A "$SCRATCH/ram")" ]; then
  echo "FAIL: tmpfs scratch left behind"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
"${HOOK_ENV[@]}" GATE_TMPFS="$SCRATCH/absent" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "scratch=$R/target/gates/" "$STUB_LOG"; then
  echo "FAIL: missing tmpfs does not fall back to the disk"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
"${HOOK_ENV[@]}" GATE_TMPFS="$SCRATCH/ram" GATE_TMPFS_FLOOR_KB=99999999999 "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "scratch=$R/target/gates/" "$STUB_LOG"; then
  echo "FAIL: full tmpfs does not fall back to the disk"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi

export SYNC="$SCRATCH/sync"
for tmpfs in "$SCRATCH/ram" "$SCRATCH/absent"; do
  rm -rf "$SYNC"
  mkdir -p "$SYNC"
  (HOOK_ENV=("${HOOK_ENV[@]}"); "${HOOK_ENV[@]}" GATE_TMPFS="$tmpfs" "$HERE/.githooks/pre-commit" >"$SCRATCH/out.a" 2>&1) &
  FIRST=$!
  MAX_POLLS=600
  POLLS=0
  while [ ! -e "$SYNC/a.started" ] && [ "$POLLS" -lt "$MAX_POLLS" ]; do
    sleep 0.1
    POLLS=$((POLLS + 1))
  done
  "${HOOK_ENV[@]}" GATE_TMPFS="$tmpfs" "$HERE/.githooks/pre-commit" >"$SCRATCH/out.b" 2>&1 &
  SECOND=$!
  wait "$FIRST" || FAILS=$((FAILS + 1))
  touch "$SYNC/a.done"
  wait "$SECOND" || FAILS=$((FAILS + 1))
  if [ ! -e "$SYNC/b.kept" ]; then
    echo "FAIL: the first hook removed the scratch of the second ($tmpfs)"
    FAILS=$((FAILS + 1))
  fi
  if [ -d "$R/target/gates" ] && [ -n "$(find "$R/target/gates" -mindepth 1 -maxdepth 1)" ]; then
    echo "FAIL: gate directory left behind after both runs ($tmpfs)"
    FAILS=$((FAILS + 1))
  fi
done

exit "$FAILS"
