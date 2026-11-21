#!/usr/bin/env bash
set -euo pipefail
NIGHTLY_DATE=${1:?usage: ebpf-toolchain.sh YYYY-MM-DD}
BPF_LINKER_VERSION=0.13.0
TOOLCHAIN="nightly-$NIGHTLY_DATE"
LLVM_PREFIX="${EBPF_LLVM_PREFIX:-$HOME/.local/llvm-nightly}"

rustup toolchain install "$TOOLCHAIN" --profile minimal --component rust-src --component clippy --component rustfmt --no-self-update
SYSROOT=$(rustc "+$TOOLCHAIN" --print sysroot)
mkdir -p "$LLVM_PREFIX/lib"
ln -sfn "$(ls "$SYSROOT"/lib/libLLVM.so.* | head -n 1)" "$LLVM_PREFIX/lib/libLLVM.so"
if [ "$(bpf-linker --version 2>/dev/null || true)" != "bpf-linker $BPF_LINKER_VERSION" ]; then
  RUSTFLAGS="-C link-arg=-Wl,-rpath,$SYSROOT/lib" LLVM_PREFIX="$LLVM_PREFIX" cargo "+$TOOLCHAIN" install --locked --force "bpf-linker@$BPF_LINKER_VERSION"
fi
bpf-linker --version
