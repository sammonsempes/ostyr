#!/usr/bin/env bash
# Usage: lab/tests/ebpf-no-panic-test.sh   (MUTANT=1 makes the check build use the production handler: the attack tests must then fail)
# Copies the kernel crate to target/, swaps in attack programs and checks lab/ebpf-no-panic.sh refuses each one and passes the real crate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH="$ROOT/target/ebpf-no-panic-test"
DEP="$ROOT/target/ebpf-no-panic-dep"
KERNEL="$ROOT/crates/ebpf-probes/ebpf"
export EBPF_UNLOCKED=1
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

write_crate() {
  local body="$1"
  rm -rf "$SCRATCH" "$DEP"
  mkdir -p "$SCRATCH/src" "$DEP/src"
  cp "$KERNEL/Cargo.toml" "$KERNEL/Cargo.lock" "$SCRATCH/"
  printf '\n[dependencies.panicdep]\npath = "%s"\n' "$DEP" >>"$SCRATCH/Cargo.toml"
  printf '[package]\nname = "panicdep"\nversion = "0.0.0"\nedition = "2021"\n\n[workspace]\n' >"$DEP/Cargo.toml"
  printf '#![no_std]\n#[inline(never)]\npub fn boom(index: usize) -> u32 {\n    let table = [1u32, 2, 3, 4];\n    table[index]\n}\n' >"$DEP/src/lib.rs"
  local check_handler='unsafe { ebpf_panic_reached() }'
  if [ -n "${MUTANT:-}" ]; then check_handler='unsafe { core::hint::unreachable_unchecked() }'; fi
  cat >"$SCRATCH/src/main.rs" <<EOF
#![no_std]
#![no_main]
use aya_ebpf::{macros::xdp, programs::XdpContext};
#[cfg(feature = "panic-check")]
extern "C" { fn ebpf_panic_reached() -> !; }
#[cfg(not(feature = "panic-check"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { unsafe { core::hint::unreachable_unchecked() } }
#[cfg(feature = "panic-check")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { $check_handler }
#[xdp]
pub fn attack(ctx: XdpContext) -> u32 {
    let value = ctx.data() as u32;
    let n = (ctx.data_end() as usize) & 7;
    $body
}
EOF
}

refused() {
  local output
  if output=$("$ROOT/lab/ebpf-no-panic.sh" "$SCRATCH/Cargo.toml" 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -E 'ebpf_panic_reached|panic path survives' | head -3
  grep -q 'panic path survives' <<<"$output"
}

attack() {
  local name="$1" body="$2"
  write_crate "$body"
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

write_crate 'value ^ n as u32'
passes() {
  "$ROOT/lab/ebpf-no-panic.sh" "$SCRATCH/Cargo.toml" >/dev/null
}
check "a program without any panic path passes" passes

real_crate_passes() {
  "$ROOT/lab/ebpf-no-panic.sh" "$KERNEL/Cargo.toml"
}
check "the real kernel crate passes" real_crate_passes

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
