#!/usr/bin/env bash
# Usage: lab/ebpf-no-panic.sh <kernel Cargo.toml> [shipped object]
# Builds the kernel crate with the panic-check feature (its panic handler calls the undefined symbol ebpf_panic_reached; bpf-linker still
# links, leaving it undefined, 'U' in llvm-nm) and refuses the object when it references that symbol: a panic path survives.
# With a shipped object, also refuses one that references the symbol or holds a panic symbol.
set -euo pipefail
MANIFEST=${1:?usage: ebpf-no-panic.sh <kernel Cargo.toml> [shipped object]}
SHIPPED=${2:-}
NIGHTLY=${EBPF_NIGHTLY:-nightly-2026-11-08}
SYMBOL=ebpf_panic_reached
BIN="$(rustc "+$NIGHTLY" --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin"
CHECK_DIR="$(dirname "$MANIFEST")/target/panic-check"
NAME=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$MANIFEST" | head -n 1)
LOCKED=(--locked)
if [ -n "${EBPF_UNLOCKED:-}" ]; then LOCKED=(); fi
OFFLINE=()
if [ -n "${EBPF_OFFLINE:-}" ]; then OFFLINE=(--offline); fi

RUSTFLAGS="-C link-arg=--btf" cargo "+$NIGHTLY" build "${OFFLINE[@]}" "${LOCKED[@]}" --release --target bpfel-unknown-none -Z build-std=core \
  --features panic-check --manifest-path "$MANIFEST" --target-dir "$CHECK_DIR" >&2
CHECK_OBJECT="$CHECK_DIR/bpfel-unknown-none/release/$NAME"

references_symbol() {
  "$BIN/llvm-nm" -a "$1" | grep -w -E "U $SYMBOL"
}

if references_symbol "$CHECK_OBJECT"; then
  echo "ebpf-no-panic: a panic path survives in $CHECK_OBJECT (it references $SYMBOL, listed above)" >&2
  exit 1
fi
if [ -n "$SHIPPED" ]; then
  if references_symbol "$SHIPPED"; then
    echo "ebpf-no-panic: the shipped object $SHIPPED references $SYMBOL: the panic-check feature was on" >&2
    exit 1
  fi
  FOUND=$("$BIN/llvm-nm" -a "$SHIPPED"; "$BIN/llvm-objdump" -d "$SHIPPED")
  if grep -i -E 'panic|unwrap_failed|expect_failed|slice_index|unreachable' <<<"$FOUND"; then
    echo "ebpf-no-panic: $SHIPPED holds a panic symbol or call (listed above)" >&2
    exit 1
  fi
fi
echo "ebpf-no-panic: no panic path reaches the handler of $NAME"
