#!/usr/bin/env bash
# Usage: lab/ebpf-no-panic.sh <kernel Cargo.toml> [shipped object]
# Builds the kernel crate with the panic-check feature (its panic handler calls the undefined symbol ebpf_panic_reached; bpf-linker still
# links, leaving it undefined, 'U' in llvm-nm) and refuses the object when it references that symbol: a panic path survives.
# It refuses an object that names the symbol in any way (undefined, or defined by a dependency: a definition would resolve the handler's call).
# With a shipped object, also refuses one that names the symbol or holds a panic symbol.
# It also refuses a crate whose sources or manifest mention the feature or any cfg feature outside the three gates of the panic handler, so that
# the checked program is the shipped program (a cfg on the feature could give the check build different code).
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

CRATE_DIR="$(dirname "$MANIFEST")"
GATES=$'#[cfg(feature = "panic-check")]|#[panic_handler]\n#[cfg(feature = "panic-check")]|extern "C" {\n#[cfg(not(feature = "panic-check"))]|#[panic_handler]'
GATE_AWK='/feature|[Pp]anic.?check/ { gate = $0; sub(/^[ \t]+/, "", gate); getline next_line; sub(/^[ \t]+/, "", next_line); print gate "|" next_line }'

feature_mentions_are_gates_only() {
  local found manifest_mentions
  found=$(find "$CRATE_DIR" -name target -prune -o -name '*.rs' -type f -exec awk "$GATE_AWK" {} \; | sort)
  if [ "$found" != "$(sort <<<"$GATES")" ]; then
    echo "ebpf-no-panic: feature or panic-check is mentioned outside the three handler gates (gate|next line, as found):" >&2
    echo "$found" >&2
    return 1
  fi
  manifest_mentions=$(grep -n -i -E 'panic.?check' "$MANIFEST" | grep -v -x -E '[0-9]+:panic-check = \[\]' || true)
  if [ -n "$manifest_mentions" ]; then
    echo "ebpf-no-panic: the manifest mentions panic-check beyond its feature line: $manifest_mentions" >&2
    return 1
  fi
}

feature_mentions_are_gates_only

RUSTFLAGS="-C link-arg=--btf" cargo "+$NIGHTLY" build "${OFFLINE[@]}" "${LOCKED[@]}" --release --target bpfel-unknown-none -Z build-std=core \
  --features panic-check --manifest-path "$MANIFEST" --target-dir "$CHECK_DIR" >&2
CHECK_OBJECT="$CHECK_DIR/bpfel-unknown-none/release/$NAME"

references_symbol() {
  "$BIN/llvm-nm" -a "$1" | grep -w "$SYMBOL"
}

if references_symbol "$CHECK_OBJECT"; then
  echo "ebpf-no-panic: a panic path survives in $CHECK_OBJECT (it names $SYMBOL, listed above)" >&2
  exit 1
fi
if [ -n "$SHIPPED" ]; then
  if references_symbol "$SHIPPED"; then
    echo "ebpf-no-panic: the shipped object $SHIPPED names $SYMBOL: the panic-check feature was on" >&2
    exit 1
  fi
  FOUND=$("$BIN/llvm-nm" -a "$SHIPPED"; "$BIN/llvm-objdump" -d "$SHIPPED")
  if grep -i -E 'panic|unwrap_failed|expect_failed|slice_index|unreachable' <<<"$FOUND"; then
    echo "ebpf-no-panic: $SHIPPED holds a panic symbol or call (listed above)" >&2
    exit 1
  fi
fi
echo "ebpf-no-panic: no panic path reaches the handler of $NAME"
