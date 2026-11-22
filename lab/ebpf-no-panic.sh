#!/usr/bin/env bash
# Usage: lab/ebpf-no-panic.sh <shipped kernel object>
# The shipped panic handler calls the undefined symbol ebpf_panic_reached, so LLVM cannot delete a panic path (the handler is not undefined
# behaviour) and the object names the symbol exactly when a panic path survives. Any llvm-nm line naming it (undefined, or defined by a
# dependency) refuses the object.
set -euo pipefail
OBJECT=${1:?usage: ebpf-no-panic.sh <shipped kernel object>}
NIGHTLY=${EBPF_NIGHTLY:-nightly-2026-11-08}
SYMBOL=ebpf_panic_reached
BIN=${EBPF_LLVM_BIN:-"$(rustc "+$NIGHTLY" --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin"}
refuse() {
  echo "ebpf-no-panic: $1" >&2
  exit 1
}
[ -e "$OBJECT" ] || refuse "object $OBJECT is missing"
[ -f "$OBJECT" ] || refuse "object $OBJECT is not a regular file"
[ -r "$OBJECT" ] || refuse "object $OBJECT is not readable"
[ -s "$OBJECT" ] || refuse "object $OBJECT is empty"
HEADER=$("$BIN/llvm-readobj" --file-headers "$OBJECT" 2>&1) || refuse "object $OBJECT is not an ELF file (llvm-readobj failed)"
grep -q 'Machine: EM_BPF' <<<"$HEADER" || refuse "object $OBJECT is not a BPF ELF file (its machine is not EM_BPF)"
SYMBOLS=$("$BIN/llvm-nm" -a "$OBJECT") || refuse "llvm-nm failed on $OBJECT"
if grep -w "$SYMBOL" <<<"$SYMBOLS"; then
  refuse "a panic path survives in $OBJECT (it names $SYMBOL, listed above)"
fi
echo "ebpf-no-panic: $OBJECT does not name $SYMBOL"
