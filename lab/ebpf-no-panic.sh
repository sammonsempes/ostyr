#!/usr/bin/env bash
# Usage: lab/ebpf-no-panic.sh <shipped kernel object>
# The shipped panic handler calls the undefined symbol ebpf_panic_reached, so LLVM cannot delete a panic path (the handler is not undefined
# behaviour) and the object names the symbol exactly when a panic path survives. The object is refused when it names the symbol (undefined,
# or defined by a dependency) or when it holds any undefined or weak symbol (the object must be self-contained: a nightly panic strategy
# leaves a weak __bpf_trap call). Nightly features are refused at build time by cargo -Zallow-features (see the hook), not by this script.
set -euo pipefail
OBJECT=${1:?usage: ebpf-no-panic.sh <shipped kernel object>}
NIGHTLY=${EBPF_NIGHTLY:-nightly-2026-11-08}
SYMBOL=ebpf_panic_reached
BIN=${EBPF_LLVM_BIN:-"$(rustc "+$NIGHTLY" --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin"}
refuse() {
  echo "ebpf-no-panic: $1" >&2
  exit 1
}
if [ -n "${EBPF_LLVM_BIN:-}" ]; then echo "ebpf-no-panic: override EBPF_LLVM_BIN=$EBPF_LLVM_BIN" >&2; fi
for tool in llvm-readobj llvm-nm; do
  [ -x "$BIN/$tool" ] || refuse "the tool $tool is missing from $BIN"
done
[ -e "$OBJECT" ] || refuse "object $OBJECT is missing"
[ -f "$OBJECT" ] || refuse "object $OBJECT is not a regular file"
[ -r "$OBJECT" ] || refuse "object $OBJECT is not readable"
[ -s "$OBJECT" ] || refuse "object $OBJECT is empty"
HEADER=$("$BIN/llvm-readobj" --file-headers - <"$OBJECT" 2>&1) || refuse "object $OBJECT is not an ELF file (llvm-readobj failed)"
grep -qE '^[[:space:]]*Machine:[[:space:]]+EM_BPF' <<<"$HEADER" || refuse "object $OBJECT is not a BPF ELF file (its machine is not EM_BPF)"
SYMBOLS=$("$BIN/llvm-nm" -a "$OBJECT") || refuse "llvm-nm failed on $OBJECT"
if grep -w "$SYMBOL" <<<"$SYMBOLS"; then
  refuse "a panic path survives in $OBJECT (it names $SYMBOL, listed above)"
fi
if grep -E '^[[:space:]]*[UwWvV] ' <<<"$SYMBOLS"; then
  refuse "$OBJECT holds an undefined or weak symbol (listed above)"
fi
echo "ebpf-no-panic: $OBJECT does not name $SYMBOL"
