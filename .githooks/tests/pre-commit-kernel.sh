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
mkdir -p "$HOME" "$SCRATCH/bin"
cat >"$SCRATCH/bin/cargo" <<'S'
#!/usr/bin/env bash
echo "cargo $*" >>"$STUB_LOG"
[ -z "${STUB_FAIL:-}" ] || [[ " $* " != *" $STUB_FAIL "* ]]
S
chmod +x "$SCRATCH/bin/cargo"
export STUB_LOG="$SCRATCH/log"
export COVERAGE_EXPORT="$SCRATCH/cov.json"
R="$SCRATCH/repo"
mkdir -p "$R"
cd "$R"
git init -q
FAILS=0

run_hook() {
  : >"$STUB_LOG"
  env "$@" PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >"$SCRATCH/out" 2>&1 || true
}

stage() {
  git rm -q -r --cached . >/dev/null 2>&1 || true
  mkdir -p "$(dirname "$1")"
  echo x >"$1"
  git add -A
}

expect_kernel() {
  local label=$1
  if ! grep -qE '^cargo \+nightly fmt --check --manifest-path crates/ebpf-probes/ebpf/Cargo.toml$' "$STUB_LOG"; then
    echo "FAIL: $label: no kernel fmt"
    FAILS=$((FAILS + 1))
  fi
  if ! grep -qE '^cargo \+nightly-2026-11-08 clippy --offline --locked --release --target bpfel-unknown-none -Z build-std=core --manifest-path crates/ebpf-probes/ebpf/Cargo.toml -- -D warnings$' "$STUB_LOG"; then
    echo "FAIL: $label: no kernel clippy"
    FAILS=$((FAILS + 1))
  fi
}

stage plain.rs
run_hook
if grep -q bpfel "$STUB_LOG"; then
  echo "FAIL: kernel step ran for an unrelated commit"
  FAILS=$((FAILS + 1))
fi

stage crates/ebpf-probes/ebpf/src/main.rs
run_hook
expect_kernel "kernel file staged"

stage .githooks/pre-commit
run_hook
expect_kernel "hook staged"

stage plain.rs
run_hook GATE_SCOPE=full
expect_kernel "full scope"

stage crates/ebpf-probes/ebpf/src/main.rs
run_hook STUB_FAIL=bpfel-unknown-none
if ! grep -qF "FAILED at step: kernel crate" "$SCRATCH/out"; then
  echo "FAIL: failing kernel step not named"
  cat "$SCRATCH/out"
  FAILS=$((FAILS + 1))
fi

stage crates/ebpf-probes/ebpf/src/main.rs
run_hook STUB_FAIL=fmt
if ! grep -qF "FAILED at step" "$SCRATCH/out"; then
  echo "FAIL: failing fmt not reported"
  FAILS=$((FAILS + 1))
fi

if [ "$FAILS" -ne 0 ]; then
  echo "pre-commit-kernel: $FAILS failures"
  exit 1
fi
echo "pre-commit-kernel: ok"
