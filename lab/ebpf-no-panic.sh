#!/usr/bin/env bash
set -euo pipefail
OBJECT=${1:?usage: ebpf-no-panic.sh <kernel object>}
NIGHTLY=${EBPF_NIGHTLY:-nightly-2026-11-08}
BIN="$(rustc "+$NIGHTLY" --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin"
FOUND=$("$BIN/llvm-nm" -a "$OBJECT"; "$BIN/llvm-objdump" -d "$OBJECT")
if grep -i -E 'panic|unwrap_failed|expect_failed|slice_index|unreachable' <<<"$FOUND"; then
  echo "ebpf-no-panic: $OBJECT holds a panic symbol or call (listed above)" >&2
  exit 1
fi
echo "ebpf-no-panic: $OBJECT holds no panic symbol"
