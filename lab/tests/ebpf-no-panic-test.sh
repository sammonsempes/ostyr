#!/usr/bin/env bash
# Usage: lab/tests/ebpf-no-panic-test.sh
# Builds the kernel crate with attack programs under the production handler (it calls the undefined ebpf_panic_reached) and checks that
# lab/ebpf-no-panic.sh refuses each object and passes the real crate. Mutants, each of which must make a check FAIL:
# MUTANT=no-nm (the checker never reads nm), MUTANT=u-only (it counts undefined symbols only), MUTANT=unchecked (the handler is the old
# unreachable_unchecked one), MUTANT=defining (the handler defines the symbol it calls).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH="$ROOT/target/ebpf-no-panic-test"
DEP="$ROOT/target/ebpf-no-panic-dep"
BUILD_TARGET="$ROOT/target/ebpf-no-panic-build"
KERNEL="$ROOT/crates/ebpf-probes/ebpf"
NIGHTLY=${EBPF_NIGHTLY:-nightly-2026-11-08}
CHECKER="$ROOT/lab/ebpf-no-panic.sh"
MUTATED="$ROOT/target/ebpf-no-panic-mutated.sh"
mkdir -p "$ROOT/target"
case "${MUTANT:-}" in
  no-nm) sed 's/^if "\$BIN\/llvm-nm" -a "\$OBJECT" | grep -w "\$SYMBOL"; then$/if false; then/' "$CHECKER" >"$MUTATED" ;;
  u-only) sed 's/grep -w "\$SYMBOL"/grep -w "U $SYMBOL"/' "$CHECKER" >"$MUTATED" ;;
  *) cp "$CHECKER" "$MUTATED" ;;
esac
chmod 755 "$MUTATED"
failures=0

check() {
  local description="$1"
  shift
  if "$@"; then
    echo "ok   $description"
  else
    echo "FAIL $description"
    failures=$((failures + 1))
  fi
}

HANDLER='unsafe { ebpf_panic_reached() }'
EXTERN='extern "C" { fn ebpf_panic_reached() -> !; }'
case "${MUTANT:-}" in
  unchecked) HANDLER='unsafe { core::hint::unreachable_unchecked() }' ;;
  defining) EXTERN='#[no_mangle] pub extern "C" fn ebpf_panic_reached() -> ! { unsafe { core::hint::unreachable_unchecked() } }' ;;
esac

write_crate() {
  local body="$1" extra_items="${2:-}" dep_source="${3:-}" build_rs="${4:-}"
  rm -rf "$SCRATCH" "$DEP"
  mkdir -p "$SCRATCH/src" "$DEP/src"
  cp "$KERNEL/Cargo.toml" "$KERNEL/Cargo.lock" "$SCRATCH/"
  printf '\n[dependencies.panicdep]\npath = "%s"\n' "$DEP" >>"$SCRATCH/Cargo.toml"
  printf '[package]\nname = "panicdep"\nversion = "0.0.0"\nedition = "2021"\n\n[workspace]\n' >"$DEP/Cargo.toml"
  printf '#![no_std]\n#[inline(never)]\npub fn boom(index: usize) -> u32 {\n    let table = [1u32, 2, 3, 4];\n    table[index]\n}\n' >"$DEP/src/lib.rs"
  if [ -n "$dep_source" ]; then printf '%s\n' "$dep_source" >"$DEP/src/lib.rs"; fi
  if [ -n "$build_rs" ]; then printf '%s\n' "$build_rs" >"$SCRATCH/build.rs"; fi
  cat >"$SCRATCH/src/main.rs" <<SOURCE
#![no_std]
#![no_main]
use aya_ebpf::{macros::xdp, programs::XdpContext};
$EXTERN
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { $HANDLER }
$extra_items
#[xdp]
pub fn attack(ctx: XdpContext) -> u32 {
    let value = ctx.data() as u32;
    let n = (ctx.data_end() as usize) & 7;
    $body
}
SOURCE
}

build_object() {
  RUSTFLAGS="-C link-arg=--btf" cargo "+$NIGHTLY" build --offline --release --target bpfel-unknown-none -Z build-std=core \
    --manifest-path "$SCRATCH/Cargo.toml" --target-dir "$BUILD_TARGET" >&2
}

OBJECT="$BUILD_TARGET/bpfel-unknown-none/release/ebpf-probes-kernel"

refused() {
  local output
  build_object
  if output=$(EBPF_NIGHTLY="$NIGHTLY" "$MUTATED" "$OBJECT" 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -E 'ebpf_panic_reached' | head -3
  grep -q 'a panic path survives' <<<"$output"
}

attack() {
  local name="$1" body="$2" extra_items="${3:-}" dep_source="${4:-}" build_rs="${5:-}"
  write_crate "$body" "$extra_items" "$dep_source" "$build_rs"
  check "$name is refused naming ebpf_panic_reached" refused
}

attack "assert, split_at, copy_from_slice, div_euclid" \
  'let buf = [1u8, 2, 3, 4, 5, 6, 7, 8]; assert!(value < 1000, "bound"); let (head, _) = buf.split_at(n); let mut out = [0u8; 4]; out.copy_from_slice(head); (value as i32).div_euclid(n as i32) as u32 ^ out[0] as u32'
attack "step_by(0)" \
  'let mut sum = 0u32; for item in (0..8u32).step_by(n) { sum ^= item; } sum ^ value'
attack "chunks(0)" \
  'let buf = [1u8, 2, 3, 4, 5, 6, 7, 8]; buf.chunks(n).count() as u32 ^ value'
attack "out-of-range index behind a branch" \
  'let table = [1u32, 2, 3, 4]; if value & 1 == 1 { table[n] } else { value }'
attack "panic inside a dependency crate" \
  'panicdep::boom(n) ^ value'
attack "panic only in an inlined generic" \
  'pick::<4>(n) ^ value' \
  '#[inline(always)]
fn pick<const SIZE: usize>(index: usize) -> u32 { let table = [1u32; SIZE]; table[index] }'

DEFINING_DEP='#![no_std]
#[no_mangle]
pub extern "C" fn ebpf_panic_reached() -> ! { unsafe { core::hint::unreachable_unchecked() } }'
attack "F1 a dependency defining ebpf_panic_reached" 'let table = [1u32, 2, 3, 4]; table[n]' 'use panicdep as _;' "$DEFINING_DEP"
ALIAS_DEP='#![no_std]
#[export_name = "ebpf_panic_reached"]
pub extern "C" fn exported() -> ! { unsafe { core::hint::unreachable_unchecked() } }'
attack "a dependency exporting the symbol under another Rust name" 'let table = [1u32, 2, 3, 4]; table[n]' 'use panicdep as _;' "$ALIAS_DEP"
attack "F2 cfg(not(feature)) fn beside a cfg(feature) fn" 'pick(n) ^ value' \
  '#[cfg(not(feature = "panic-check"))]
fn pick(n: usize) -> u32 { let table = [1u32, 2, 3, 4]; table[n] }
#[cfg(feature = "panic-check")]
fn pick(n: usize) -> u32 { n as u32 }'
attack "F2 cfg! macro" 'if cfg!(feature = "panic-check") { value } else { let table = [1u32, 2, 3, 4]; table[n] }'
attack "F2 build.rs reading CARGO_FEATURE_PANIC_CHECK into a cfg" 'pick(n) ^ value' \
  '#[cfg(not(check_build))]
fn pick(n: usize) -> u32 { let table = [1u32, 2, 3, 4]; table[n] }
#[cfg(check_build)]
fn pick(n: usize) -> u32 { n as u32 }' '' \
  'fn main() { if std::env::var_os("CARGO_FEATURE_PANIC_CHECK").is_some() { println!("cargo:rustc-cfg=check_build"); } }'
attack "F2 build.rs testing the target directory" 'pick(n) ^ value' \
  '#[cfg(not(check_build))]
fn pick(n: usize) -> u32 { let table = [1u32, 2, 3, 4]; table[n] }
#[cfg(check_build)]
fn pick(n: usize) -> u32 { n as u32 }' '' \
  'fn main() { if std::env::var("OUT_DIR").map(|dir| dir.contains("panic-check")).unwrap_or(false) { println!("cargo:rustc-cfg=check_build"); } }'

write_crate 'value ^ n as u32'
passes() {
  build_object
  EBPF_NIGHTLY="$NIGHTLY" "$MUTATED" "$OBJECT" >/dev/null
}
check "a program without any panic path passes" passes

real_crate_passes() {
  RUSTFLAGS="-C link-arg=--btf" cargo "+$NIGHTLY" build --offline --locked --release --target bpfel-unknown-none -Z build-std=core \
    --manifest-path "$KERNEL/Cargo.toml" --target-dir "$BUILD_TARGET" >&2
  EBPF_NIGHTLY="$NIGHTLY" "$MUTATED" "$OBJECT"
}
check "the real kernel crate passes" real_crate_passes

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
