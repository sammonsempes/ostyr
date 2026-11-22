#!/usr/bin/env bash
# Usage: lab/ebpf-no-panic.sh <shipped kernel object>
# The shipped panic handler calls the undefined symbol ebpf_panic_reached, so LLVM cannot delete a panic path (the handler is not undefined
# behaviour) and the object names the symbol exactly when a panic path survives. Any llvm-nm line naming it (undefined, or defined by a
# dependency) refuses the object.
set -euo pipefail
OBJECT=${1:?usage: ebpf-no-panic.sh <shipped kernel object>}
NIGHTLY=${EBPF_NIGHTLY:-nightly-2026-11-08}
SYMBOL=ebpf_panic_reached
BIN="$(rustc "+$NIGHTLY" --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin"
if "$BIN/llvm-nm" -a "$OBJECT" | grep -w "$SYMBOL"; then
  echo "ebpf-no-panic: a panic path survives in $OBJECT (it names $SYMBOL, listed above)" >&2
  exit 1
fi
echo "ebpf-no-panic: $OBJECT does not name $SYMBOL"
