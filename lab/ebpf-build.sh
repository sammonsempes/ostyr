#!/usr/bin/env bash
# Usage: lab/ebpf-build.sh <kernel crate Cargo.toml> <target dir>
# The one recipe that builds the shipped kernel object (hook, ebpf workflow and lab test all call it); the object lands in
# <target dir>/bpfel-unknown-none/release/<package>. Two steps, so that the compiler can refuse nightly features without refusing its own:
# 1. the sysroot (core, compiler_builtins) is built with -Z build-std from a fixed trivial crate, with no feature allowlist (compiler_builtins
#    itself uses #![feature(linkage)]);
# 2. the kernel crate is built against that sysroot with no build-std, by the stable cargo (it refuses cargo-features and every nightly cargo
#    setting in any manifest of the build) driving the pinned nightly rustc, with -Zallow-features=$ALLOWED_FEATURES in rustc flags (it refuses
#    any other #![feature] in the kernel crate and in every dependency). Changing ALLOWED_FEATURES is an owner decision: aya-ebpf needs
#    asm_experimental_arch, nothing else, and linkage must never be listed (a linkonce_odr ebpf_panic_reached hides a panic path).
set -euo pipefail
MANIFEST=${1:?usage: ebpf-build.sh <kernel crate Cargo.toml> <target dir>}
TARGET_DIR=${2:?usage: ebpf-build.sh <kernel crate Cargo.toml> <target dir>}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
NIGHTLY=${EBPF_NIGHTLY:-nightly-2026-11-08}
ALLOWED_FEATURES=asm_experimental_arch
TARGET=bpfel-unknown-none
UNIT_SEPARATOR=$'\x1f'
OFFLINE=()
LOCKED=(--locked)
if [ -n "${EBPF_OFFLINE:-}" ]; then OFFLINE=(--offline); fi
if [ -n "${EBPF_UNLOCKED:-}" ]; then LOCKED=(); fi
fail() {
  echo "ebpf-build: $1" >&2
  exit 1
}
cd "$ROOT"
case "$(cargo --version)" in
  *nightly*) fail "the default cargo is a nightly: step 2 needs the stable cargo of rust-toolchain.toml, which refuses cargo-features" ;;
esac
NIGHTLY_SYSROOT=$(rustc "+$NIGHTLY" --print sysroot) || fail "rustc +$NIGHTLY is not installed"
NIGHTLY_RUSTC="$NIGHTLY_SYSROOT/bin/rustc"
[ -x "$NIGHTLY_RUSTC" ] || fail "$NIGHTLY_RUSTC is missing"

SYSROOT_DIR="$TARGET_DIR/ebpf-sysroot"
SYSROOT_CRATE="$SYSROOT_DIR/crate"
SYSROOT_LIB="$SYSROOT_DIR/root/lib/rustlib/$TARGET/lib"
rm -rf "$SYSROOT_DIR/root"
mkdir -p "$SYSROOT_CRATE/src" "$SYSROOT_LIB" "$SYSROOT_DIR/root/lib/rustlib"
printf '[package]\nname = "ebpf-sysroot"\nversion = "0.0.0"\nedition = "2021"\n\n[workspace]\n\n[profile.release]\nopt-level = 3\npanic = "abort"\ncodegen-units = 1\n' \
  >"$SYSROOT_CRATE/Cargo.toml"
printf '#![no_std]\n' >"$SYSROOT_CRATE/src/lib.rs"
ARTIFACTS=$(env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS cargo "+$NIGHTLY" build "${OFFLINE[@]}" --release --target "$TARGET" -Z build-std=core \
  --message-format=json --manifest-path "$SYSROOT_CRATE/Cargo.toml" --target-dir "$SYSROOT_DIR/target") || fail "the sysroot build failed"
LIBRARIES=$(jq -r 'select(.reason == "compiler-artifact" and (.target.name == "core" or .target.name == "compiler_builtins")) | .filenames[]' \
  <<<"$ARTIFACTS") || fail "cannot read the sysroot build artifacts"
[ -n "$LIBRARIES" ] || fail "the sysroot build produced no core library"
while IFS= read -r library; do
  cp "$library" "$SYSROOT_LIB/"
done <<<"$LIBRARIES"
ln -s "$NIGHTLY_SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu" "$SYSROOT_DIR/root/lib/rustlib/x86_64-unknown-linux-gnu"

FLAGS="-Clink-arg=--btf${UNIT_SEPARATOR}--sysroot=$SYSROOT_DIR/root${UNIT_SEPARATOR}-Zallow-features=$ALLOWED_FEATURES"
env -u RUSTFLAGS CARGO_ENCODED_RUSTFLAGS="$FLAGS" RUSTC="$NIGHTLY_RUSTC" cargo build "${OFFLINE[@]}" "${LOCKED[@]}" --release --target "$TARGET" \
  --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" >&2 || fail "the kernel crate build failed (a feature outside $ALLOWED_FEATURES, or a nightly cargo setting, is refused here)"
