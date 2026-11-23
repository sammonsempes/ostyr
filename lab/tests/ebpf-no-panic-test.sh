#!/usr/bin/env bash
# Usage: lab/tests/ebpf-no-panic-test.sh
# Builds the kernel crate with attack programs under the production handler (it calls the undefined ebpf_panic_reached) and checks that
# lab/ebpf-no-panic.sh refuses each object and passes the real crate. Mutants, each of which must make a check FAIL:
# MUTANT=no-nm (the checker never reads the symbol name), MUTANT=u-only (it counts undefined symbols only), MUTANT=weak-ok (weak and undefined
# symbols are allowed), MUTANT=no-allow (lab/ebpf-build.sh drops its -Zallow-features list), MUTANT=nightly-cargo (it builds with the nightly
# cargo, which accepts cargo-features), MUTANT=unchecked (the handler is the old unreachable_unchecked one), MUTANT=defining (the handler
# defines the symbol it calls), MUTANT=path-build-code-ok (a path package may have a build script), MUTANT=proc-macro-ok (proc-macro targets are
# not examined), MUTANT=checksum-name-only (the lock checksum is matched on name and version, not source), MUTANT=filter-platform (cargo metadata
# is filtered to the target again), MUTANT=patch-ok (a [patch] table is accepted), MUTANT=lock-source-ok (the Cargo.lock source check before cargo
# metadata is off), MUTANT=stale-target (the kernel crate builds in the shared target directory), MUTANT=no-lock-check (a missing Cargo.lock
# is not refused), MUTANT=clippy-shared (the hook's kernel clippy goes back to a shared target directory), MUTANT=reverify-off (extracted registry sources are not compared with their archive).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRATCH="$ROOT/target/ebpf-no-panic-test"
DEP="$ROOT/target/ebpf-no-panic-dep"
BUILD_TARGET="$ROOT/target/ebpf-no-panic-build"
KERNEL="$ROOT/crates/ebpf-probes/ebpf"
NIGHTLY=${EBPF_NIGHTLY:-nightly-2026-11-08}
CHECKER="$ROOT/lab/ebpf-no-panic.sh"
MUTATED="$ROOT/target/ebpf-no-panic-mutated.sh"
BUILDER="$ROOT/target/ebpf-build-mutated.sh"
mkdir -p "$ROOT/target"
case "${MUTANT:-}" in
  no-nm) sed 's/^if grep -w "\$SYMBOL" <<<"\$SYMBOLS"; then$/if false; then/' "$CHECKER" >"$MUTATED" ;;
  u-only) sed 's/grep -w "\$SYMBOL"/grep -w "U $SYMBOL"/' "$CHECKER" >"$MUTATED" ;;
  no-nm-status) sed 's/ || refuse "llvm-nm failed on \$OBJECT"//' "$CHECKER" >"$MUTATED" ;;
  weak-ok) sed "s/^if grep -E '^\[\[:space:\]\]\*\[UwWvV\] ' <<<\"\$SYMBOLS\"; then\$/if false; then/" "$CHECKER" >"$MUTATED" ;;
  *) cp "$CHECKER" "$MUTATED" ;;
esac
sed "s|^ROOT=.*|ROOT=\"$ROOT\"|" "$ROOT/lab/ebpf-build.sh" >"$BUILDER"
case "${MUTANT:-}" in
  no-allow) sed -i 's/\${UNIT_SEPARATOR}-Zallow-features=\$ALLOWED_FEATURES//' "$BUILDER" ;;
  path-build-code-ok) sed -i '/= path \]; then$/{n;s/allowed=1/allowed=0/}' "$BUILDER" ;;
  proc-macro-ok) sed -i 's/ or \. == "proc-macro"//' "$BUILDER" ;;
  checksum-name-only) sed -i 's/ && found_source == source//' "$BUILDER" ;;
  filter-platform) sed -i 's/--format-version 1 --manifest-path/--format-version 1 --filter-platform "$TARGET" --manifest-path/' "$BUILDER" ;;
  lock-source-ok) sed -i 's/^  check_lock_sources "\$lock"$/  true/' "$BUILDER" ;;
  stale-target) sed -i 's|^BUILD_DIR=.*|BUILD_DIR="$TARGET_DIR"|;/^rm -rf "\$TARGET_DIR\/\$TARGET"$/d;/^mv "\$BUILD_DIR/d' "$BUILDER" ;;
  no-lock-check) sed -i '/^  \[ -f "\$lock" \] || fail/d' "$BUILDER" ;;
  reverify-off) sed -i 's/^    verify_registry_package .*$/    true/' "$BUILDER" ;;
  patch-ok) sed -i 's/^  check_patch_tables "\${manifests\[@\]}"$/  true/' "$BUILDER" ;;
  nightly-cargo) sed -i 's/ cargo build "\${OFFLINE\[@\]}"/ cargo "+$NIGHTLY" build "${OFFLINE[@]}"/;s/ cargo metadata / cargo "+$NIGHTLY" metadata /' "$BUILDER" ;;
esac
case "${MUTANT:-}" in
  no-nm | u-only | no-nm-status | weak-ok)
    if cmp -s "$CHECKER" "$MUTATED"; then
      echo "the mutant ${MUTANT} did not change the checker" >&2
      exit 2
    fi
    ;;
  no-allow | nightly-cargo | path-build-code-ok | proc-macro-ok | checksum-name-only | filter-platform | patch-ok | lock-source-ok | reverify-off | stale-target | no-lock-check)
    if cmp -s "$ROOT/lab/ebpf-build.sh" "$BUILDER"; then
      echo "the mutant ${MUTANT} did not change the builder" >&2
      exit 2
    fi
    ;;
esac
chmod 755 "$MUTATED" "$BUILDER"
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

CRATE_ATTRS=""
CRATE_MANIFEST_HEADER=""
DEP_MANIFEST_HEADER=""
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
  printf '%s[package]\nname = "panicdep"\nversion = "0.0.0"\nedition = "2021"\n\n[workspace]\n' "$DEP_MANIFEST_HEADER" >"$DEP/Cargo.toml"
  if [ -n "$CRATE_MANIFEST_HEADER" ]; then
    printf '%s\n' "$CRATE_MANIFEST_HEADER" | cat - "$SCRATCH/Cargo.toml" | sed 's/^panic = "abort"$/panic = "immediate-abort"/' >"$SCRATCH/Cargo.toml.new"
    mv "$SCRATCH/Cargo.toml.new" "$SCRATCH/Cargo.toml"
  fi
  printf '#![no_std]\n#[inline(never)]\npub fn boom(index: usize) -> u32 {\n    let table = [1u32, 2, 3, 4];\n    table[index]\n}\n' >"$DEP/src/lib.rs"
  if [ -n "$dep_source" ]; then printf '%s\n' "$dep_source" >"$DEP/src/lib.rs"; fi
  if [ -n "$build_rs" ]; then printf '%s\n' "$build_rs" >"$SCRATCH/build.rs"; fi
  cat >"$SCRATCH/src/main.rs" <<SOURCE
#![no_std]
#![no_main]
$CRATE_ATTRS
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
  EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 EBPF_UNLOCKED=1 "$BUILDER" "$SCRATCH/Cargo.toml" "$BUILD_TARGET" >&2
}

build_nightly_object() {
  RUSTFLAGS="-C link-arg=--btf" cargo "+$NIGHTLY" build --offline --release --target bpfel-unknown-none -Z build-std=core \
    --manifest-path "$SCRATCH/Cargo.toml" --target-dir "$BUILD_TARGET" >&2
}

OBJECT="$BUILD_TARGET/bpfel-unknown-none/release/ebpf-probes-kernel"

refused() {
  local output
  build_object || return 1
  if output=$(EBPF_NIGHTLY="$NIGHTLY" "$MUTATED" "$OBJECT" 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -E "${REFUSAL_MARK:-ebpf_panic_reached}" | head -3
  grep -q "${REFUSAL_TEXT:-a panic path survives}" <<<"$output"
}

refused_nightly_object() {
  local output
  build_nightly_object || return 1
  if output=$(EBPF_NIGHTLY="$NIGHTLY" "$MUTATED" "$OBJECT" 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -E "$REFUSAL_MARK" | head -3
  grep -q "$REFUSAL_TEXT" <<<"$output"
}

refused_build() {
  local output
  rm -f "$OBJECT"
  if output=$(EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 EBPF_UNLOCKED=1 "$BUILDER" "$SCRATCH/Cargo.toml" "$BUILD_TARGET" 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -E "$REFUSAL_TEXT" | head -2
  grep -qE "$REFUSAL_TEXT" <<<"$output" && [ ! -e "$OBJECT" ]
}

CLEAN_OBJECT="$ROOT/target/ebpf-no-panic-clean.o"
EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 "$BUILDER" "$KERNEL/Cargo.toml" "$BUILD_TARGET" >&2
cp "$BUILD_TARGET/bpfel-unknown-none/release/ebpf-probes-kernel" "$CLEAN_OBJECT"

attack() {
  local name="$1" body="$2" extra_items="${3:-}" dep_source="${4:-}" build_rs="${5:-}"
  write_crate "$body" "$extra_items" "$dep_source" "$build_rs"
  check "$name is refused naming ebpf_panic_reached" refused
}

BUILD_CODE_REFUSAL='has a build script or a proc-macro target and is not in ALLOWED_BUILD_CODE'
build_rs_attack() {
  write_crate "$2" "$3" "$4" "$5"
  REFUSAL_TEXT="$BUILD_CODE_REFUSAL" check "$1 is refused by the build (a path package with a build script)" refused_build
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
build_rs_attack "F2 build.rs reading CARGO_FEATURE_PANIC_CHECK into a cfg" 'pick(n) ^ value' \
  '#[cfg(not(check_build))]
fn pick(n: usize) -> u32 { let table = [1u32, 2, 3, 4]; table[n] }
#[cfg(check_build)]
fn pick(n: usize) -> u32 { n as u32 }' '' \
  'fn main() { if std::env::var_os("CARGO_FEATURE_PANIC_CHECK").is_some() { println!("cargo:rustc-cfg=check_build"); } }'
build_rs_attack "F2 build.rs testing the target directory" 'pick(n) ^ value' \
  '#[cfg(not(check_build))]
fn pick(n: usize) -> u32 { let table = [1u32, 2, 3, 4]; table[n] }
#[cfg(check_build)]
fn pick(n: usize) -> u32 { n as u32 }' '' \
  'fn main() { if std::env::var("OUT_DIR").map(|dir| dir.contains("panic-check")).unwrap_or(false) { println!("cargo:rustc-cfg=check_build"); } }'

F3_BODY='let buf = [1u8, 2, 3, 4, 5, 6, 7, 8]; let (head, _) = buf.split_at(n * 2); head.len() as u32 ^ value'
CRATE_MANIFEST_HEADER='cargo-features = ["panic-immediate-abort"]'
write_crate "$F3_BODY"
REFUSAL_MARK='__bpf_trap' REFUSAL_TEXT='undefined or weak symbol' check "F3 immediate-abort object (nightly cargo): weak __bpf_trap refused by the object check" refused_nightly_object
REFUSAL_TEXT='nightly version of Cargo|nightly-only' check "F3 immediate-abort profile: the shipped build (stable cargo) refuses cargo-features" refused_build
CRATE_MANIFEST_HEADER=""

PM_ATTACK_DEP='#![feature(allow_internal_unstable)]
extern crate proc_macro;
use proc_macro::TokenStream;
#[proc_macro]
#[allow_internal_unstable(linkage)]
pub fn define(_input: TokenStream) -> TokenStream {
    "#[linkage = \"linkonce_odr\"] #[no_mangle] pub extern \"C\" fn ebpf_panic_reached() -> ! { loop {} }".parse().unwrap()
}'
SAVED_EXTERN="$EXTERN"
EXTERN=""
write_crate 'let table = [1u32, 2, 3, 4]; table[n]' 'panicdep::define!();' "$PM_ATTACK_DEP"
printf '\n[lib]\nproc-macro = true\n' >>"$DEP/Cargo.toml"
REFUSAL_TEXT="$BUILD_CODE_REFUSAL" check "atk-pm a path proc-macro dependency using allow_internal_unstable(linkage) is refused by name" refused_build
EXTERN="$SAVED_EXTERN"

LINK_ARG_BITCODE="$ROOT/target/ebpf-no-panic-evil.ll"
printf 'target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"\ntarget triple = "bpfel"\ndefine linkonce_odr void @ebpf_panic_reached() {\n  unreachable\n}\n' \
  >"$LINK_ARG_BITCODE"
EXTERN=""
build_rs_attack "atk-ld a build.rs printing cargo:rustc-link-arg of a bitcode" 'let table = [1u32, 2, 3, 4]; table[n]' '' '' \
  "fn main() { println!(\"cargo:rustc-link-arg=$LINK_ARG_BITCODE\"); }"
EXTERN="$SAVED_EXTERN"

unlisted_registry_package_refused() {
  local unlisted="$ROOT/target/ebpf-build-unlisted.sh" output package="$1"
  sed "/^  \"$package /d" "$BUILDER" >"$unlisted"
  sed -i "s|^ROOT=.*|ROOT=\"$ROOT\"|" "$unlisted"
  chmod 755 "$unlisted"
  if output=$(EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 "$unlisted" "$KERNEL/Cargo.toml" "$BUILD_TARGET" 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -F "the package $package " | head -2
  grep -qF "the package $package " <<<"$output"
}
check "a registry proc-macro package missing from ALLOWED_BUILD_CODE is refused by name" unlisted_registry_package_refused aya-ebpf-macros
check "F2 libc, host-only build code of the unfiltered graph, missing from ALLOWED_BUILD_CODE is refused by name" unlisted_registry_package_refused libc

checksum_of_foreign_package_is_empty() {
  local lock="$ROOT/target/ebpf-lock-source.lock" body output
  printf '[[package]]\nname = "aya-ebpf-macros"\nversion = "0.4.0"\nsource = "git+file:///nowhere#abc"\n\n' >"$lock"
  printf '[[package]]\nname = "aya-ebpf-macros"\nversion = "0.4.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' >>"$lock"
  printf 'checksum = "1111"\n' >>"$lock"
  body=$(sed -n '/^lock_checksum() {$/,/^}$/p' "$BUILDER")
  output=$(bash -c "$body"$'\n''lock_checksum aya-ebpf-macros 0.4.0 "$1" "$2"' _ "$lock" "git+file:///nowhere#abc")
  echo "checksum printed for the foreign source: [$output]"
  [ -z "$output" ]
}
check "F1 the lock checksum of a registry package is not given to a foreign package of the same name and version" checksum_of_foreign_package_is_empty

SOURCE_REFUSAL='does not come from crates.io'
PATCH_REFUSAL='holds a \[patch\] or \[replace\] table'
CONFIG_REFUSAL='/.cargo exists'
refused_unlocked() {
  local output
  rm -f "$OBJECT"
  if output=$(EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 EBPF_UNLOCKED=1 "$BUILDER" "$SCRATCH/Cargo.toml" "$BUILD_TARGET" 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -E "$REFUSAL_TEXT" | head -2
  grep -qE "$REFUSAL_TEXT" <<<"$output" && [ ! -e "$OBJECT" ]
}

refused_locked() {
  local output
  rm -f "$OBJECT"
  if output=$(EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 "$BUILDER" "$SCRATCH/Cargo.toml" "$BUILD_TARGET" 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -E "$REFUSAL_TEXT" | head -2
  grep -qE "$REFUSAL_TEXT" <<<"$output" && [ ! -e "$OBJECT" ]
}

atk_dup_refused() {
  write_crate 'value ^ n as u32'
  printf '\n[[package]]\nname = "aya-ebpf-macros"\nversion = "0.4.0"\nsource = "git+file:///nowhere#0123456789abcdef"\n' >>"$SCRATCH/Cargo.lock"
  printf '\n[dependencies.evil]\npackage = "aya-ebpf-macros"\nversion = "=0.4.0"\ngit = "file:///nowhere"\n' >>"$SCRATCH/Cargo.toml"
  REFUSAL_TEXT="$SOURCE_REFUSAL" refused_locked
}
check "atk-dup a git package named and versioned like an allowlisted one is refused by name, before any cargo command" atk_dup_refused

COLD_HOME="$ROOT/target/ebpf-cold-cargo-home"
cold_home() {
  rm -rf "$COLD_HOME"
  mkdir -p "$COLD_HOME/registry"
  cp -r "${CARGO_HOME:-$HOME/.cargo}/registry/cache" "${CARGO_HOME:-$HOME/.cargo}/registry/index" "$COLD_HOME/registry/"
}
cold_home
atk_dup_cold_home_refused() {
  CARGO_HOME="$COLD_HOME" atk_dup_refused
}
check "atk-dup is refused by name on a cold CARGO_HOME holding no git checkout" atk_dup_cold_home_refused

check_only() {
  EBPF_CHECK_ONLY=1 EBPF_UNLOCKED=1 EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 "$BUILDER" "$SCRATCH/Cargo.toml"
}

edited_registry_source_refused() {
  local output source
  write_crate 'value ^ n as u32'
  CARGO_HOME="$COLD_HOME" check_only >&2 || return 1
  source=$(find "$COLD_HOME/registry/src" -maxdepth 2 -type d -name 'aya-ebpf-macros-0.4.0' | head -1)
  printf 'compile_error!("edited");\n' >>"$source/src/lib.rs"
  if output=$(CARGO_HOME="$COLD_HOME" check_only 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -F 'registry source was edited' | head -2
  grep -qF 'the extracted source of aya-ebpf-macros 0.4.0' <<<"$output"
}
check "T692FS an edited extracted registry source with its .cargo-ok kept is refused by name" edited_registry_source_refused
cold_home

edited_archive_refused() {
  local output archive
  write_crate 'value ^ n as u32'
  archive=$(find "$COLD_HOME/registry/cache" -name 'aya-ebpf-macros-0.4.0.crate' | head -1)
  printf 'x' >>"$archive"
  if output=$(CARGO_HOME="$COLD_HOME" check_only 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -F 'does not match the Cargo.lock checksum' | head -2
  grep -qF 'archive of aya-ebpf-macros 0.4.0 in the registry cache does not match' <<<"$output"
}
check "an archive in the registry cache that does not hash to the Cargo.lock checksum is refused by name" edited_archive_refused
rm -rf "$COLD_HOME"

POISON_EDIT='Ok(prog) => { let mut poisoned = prog.expand(); poisoned.extend("#[unsafe(link_section = \\\"poison\\\")] #[used] static POISON: u8 = 1;".parse::<proc_macro2::TokenStream>().unwrap()); poisoned }'
stale_proc_macro_not_reused() {
  local source stale="$ROOT/target/ebpf-stale-target" flags separator=$'\x1f' output
  write_crate 'value ^ n as u32'
  cold_home
  CARGO_HOME="$COLD_HOME" check_only >&2 || return 1
  source=$(find "$COLD_HOME/registry/src" -maxdepth 2 -type d -name 'aya-ebpf-macros-0.4.0' | head -1)
  cp "$source/src/lib.rs" "$ROOT/target/ebpf-macros-lib.rs"
  sed -i "s|^        Ok(prog) => prog.expand(),\$|        $POISON_EDIT,|" "$source/src/lib.rs"
  rm -rf "$stale"
  flags="-Clink-arg=--btf${separator}--sysroot=$BUILD_TARGET/ebpf-sysroot/root${separator}-Zallow-features=asm_experimental_arch"
  env -u RUSTFLAGS CARGO_HOME="$COLD_HOME" CARGO_ENCODED_RUSTFLAGS="$flags" RUSTC="$(rustc "+$NIGHTLY" --print sysroot)/bin/rustc" \
    cargo build --offline --release --target bpfel-unknown-none --manifest-path "$SCRATCH/Cargo.toml" --target-dir "$stale" >&2 || return 1
  grep -q poison "$stale/bpfel-unknown-none/release/ebpf-probes-kernel" || { echo "the poisoned control build holds no poison section"; return 1; }
  cp "$ROOT/target/ebpf-macros-lib.rs" "$source/src/lib.rs"
  output=$(CARGO_HOME="$COLD_HOME" EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 EBPF_UNLOCKED=1 "$BUILDER" "$SCRATCH/Cargo.toml" "$stale" 2>&1) \
    || { echo "$output" | tail -5; return 1; }
  if grep -q poison "$stale/bpfel-unknown-none/release/ebpf-probes-kernel"; then
    echo "the shipped object holds the poison section: the stale proc-macro of the shared target directory was reused"
    return 1
  fi
  echo "the object built after the revert holds no poison section"
}
check "T692FS2 a proc-macro built from an edited registry source and left in the target directory is not reused after the edit is reverted" \
  stale_proc_macro_not_reused
rm -rf "$COLD_HOME" "$ROOT/target/ebpf-stale-target"

MARKER_EDIT='Ok(prog) => { std::fs::write(\"MARKER_PATH\", \"ran\").ok(); prog.expand() }'
HOOK="$ROOT/.githooks/pre-commit"
HOOK_COPY="$ROOT/target/ebpf-hook-mutated"
case "${MUTANT:-}" in
  clippy-shared) sed 's| --target-dir "\$EBPF_CLIPPY_DIR"||' "$HOOK" >"$HOOK_COPY" ;;
  *) cp "$HOOK" "$HOOK_COPY" ;;
esac
if [ "${MUTANT:-}" = clippy-shared ] && cmp -s "$HOOK" "$HOOK_COPY"; then
  echo "the mutant clippy-shared did not change the hook" >&2
  exit 2
fi

hook_clippy_in_fresh_directory() {
  grep -qF -- '--manifest-path "$EBPF_MANIFEST" --target-dir "$EBPF_CLIPPY_DIR" -- -D warnings' "$HOOK_COPY" \
    && [ "$(grep -cxF '  rm -rf "$EBPF_CLIPPY_DIR"' "$HOOK_COPY")" -eq 2 ]
}

hook_style_clippy() {
  local target_dir="$1"
  CARGO_HOME="$COLD_HOME" cargo "+$NIGHTLY" clippy --offline --locked --release --target bpfel-unknown-none -Z build-std=core \
    --manifest-path "$SCRATCH/Cargo.toml" --target-dir "$target_dir" >&2 || echo "clippy lints on the attack crate: status ignored, only the marker matters" >&2
}

clippy_stale_macro_not_reused() {
  local source marker="$ROOT/target/ebpf-clippy-marker" shared="$ROOT/target/ebpf-clippy-shared" fresh="$ROOT/target/ebpf-clippy-fresh"
  hook_clippy_in_fresh_directory || { echo "the hook's kernel clippy does not run in an emptied --target-dir"; return 1; }
  write_crate 'value ^ n as u32'
  cold_home
  CARGO_HOME="$COLD_HOME" check_only >&2 || return 1
  source=$(find "$COLD_HOME/registry/src" -maxdepth 2 -type d -name 'aya-ebpf-macros-0.4.0' | head -1)
  cp "$source/src/lib.rs" "$ROOT/target/ebpf-macros-lib.rs"
  sed -i "s|^        Ok(prog) => prog.expand(),\$|        ${MARKER_EDIT//MARKER_PATH/$marker},|" "$source/src/lib.rs"
  rm -rf "$marker" "$shared" "$fresh"
  hook_style_clippy "$shared" || return 1
  [ -e "$marker" ] || { echo "the control clippy never ran the edited proc-macro"; return 1; }
  rm -f "$marker"
  cp "$ROOT/target/ebpf-macros-lib.rs" "$source/src/lib.rs"
  hook_style_clippy "$shared" || return 1
  [ -e "$marker" ] || { echo "control: the stale proc-macro of the shared directory was not reused (the attack is not live here)"; return 1; }
  rm -f "$marker"
  rm -rf "$fresh"
  if [ "${MUTANT:-}" = clippy-shared ]; then hook_style_clippy "$shared" || return 1; else hook_style_clippy "$fresh" || return 1; fi
  if [ -e "$marker" ]; then
    echo "the marker was written again after the source was restored: the stale proc-macro ran on the host"
    return 1
  fi
  echo "no marker after the source is restored"
}
check "T692FS3 the kernel clippy in an emptied target directory never runs a proc-macro built from an edited source" \
  clippy_stale_macro_not_reused
rm -rf "$COLD_HOME" "$ROOT/target/ebpf-clippy-shared" "$ROOT/target/ebpf-clippy-fresh" "$ROOT/target/ebpf-clippy-marker"

host_code_never_runs_in_check_only() {
  local marker="$ROOT/target/ebpf-check-only-marker" output
  rm -f "$marker"
  write_crate 'value ^ n as u32' '' '' "fn main() { std::fs::write(\"$marker\", \"ran\").unwrap(); }"
  if output=$(check_only 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -E "$BUILD_CODE_REFUSAL" | head -2
  grep -qE "$BUILD_CODE_REFUSAL" <<<"$output" && [ ! -e "$marker" ]
}
check "a path build.rs is refused by the check-only mode and its marker is never written" host_code_never_runs_in_check_only

atk_patch_refused() {
  local evil="$ROOT/target/ebpf-evil-libc"
  rm -rf "$evil"
  mkdir -p "$evil/src"
  printf '[package]\nname = "libc"\nversion = "0.2.191"\nedition = "2021"\n' >"$evil/Cargo.toml"
  printf '#![no_std]\n' >"$evil/src/lib.rs"
  write_crate 'value ^ n as u32'
  printf '\n[patch.crates-io]\nlibc = { path = "%s" }\n' "$evil" >>"$SCRATCH/Cargo.toml"
  REFUSAL_TEXT="$PATCH_REFUSAL" refused_unlocked
}
check "atk-patch a [patch.crates-io] to a path libc is refused by name" atk_patch_refused

atk_replace_refused() {
  write_crate 'value ^ n as u32'
  printf '\n[replace]\n"libc:0.2.191" = { path = "%s" }\n' "$ROOT/target/ebpf-evil-libc" >>"$SCRATCH/Cargo.toml"
  REFUSAL_TEXT="$PATCH_REFUSAL" refused_build
}
check "a [replace] table is refused by name" atk_replace_refused

atk_fake_refused() {
  write_crate 'value ^ n as u32'
  mkdir -p "$SCRATCH/.cargo"
  printf '[source.crates-io]\nreplace-with = "v"\n\n[source.v]\ndirectory = "vendor"\n' >"$SCRATCH/.cargo/config.toml"
  REFUSAL_TEXT="$CONFIG_REFUSAL" refused_build
}
check "fake a .cargo/config.toml source replacement in the crate directory is refused by name" atk_fake_refused

atk_ancestor_refused() {
  local output
  write_crate 'value ^ n as u32'
  mkdir -p "$SCRATCH/.cargo" "$SCRATCH/nested/src"
  cp "$SCRATCH/Cargo.toml" "$SCRATCH/Cargo.lock" "$SCRATCH/nested/"
  cp "$SCRATCH/src/main.rs" "$SCRATCH/nested/src/main.rs"
  if output=$(EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 EBPF_UNLOCKED=1 "$BUILDER" "$SCRATCH/nested/Cargo.toml" "$BUILD_TARGET" 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -F '/.cargo exists' | head -2
  grep -qF "$SCRATCH/.cargo exists" <<<"$output"
}
check "a .cargo directory in an ancestor of the kernel manifest is refused by name" atk_ancestor_refused

missing_lock_refused() {
  local output
  write_crate 'value ^ n as u32'
  rm -f "$SCRATCH/Cargo.lock"
  if output=$(EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 EBPF_UNLOCKED=1 "$BUILDER" "$SCRATCH/Cargo.toml" "$BUILD_TARGET" 2>&1); then
    echo "$output" | tail -3
    return 1
  fi
  echo "$output" | grep -F 'Cargo.lock is missing' | head -2
  grep -qF 'Cargo.lock is missing' <<<"$output"
}
check "a missing Cargo.lock is refused by name, never a skipped check" missing_lock_refused

relative_target_built() {
  write_crate 'value ^ n as u32'
  rm -rf "$ROOT/target/ebpf-relative-target"
  (cd "$ROOT/target" && EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 EBPF_UNLOCKED=1 "$BUILDER" ebpf-no-panic-test/Cargo.toml ebpf-relative-target >&2) \
    && [ -f "$ROOT/target/ebpf-relative-target/bpfel-unknown-none/release/ebpf-probes-kernel" ]
}
check "a relative manifest and target directory are made absolute before the script changes directory" relative_target_built

write_crate 'value ^ n as u32'

write_crate '(unsafe { ext(n) }) ^ value' 'extern "C" { fn ext(index: usize) -> u32; }'
REFUSAL_MARK='ext' REFUSAL_TEXT='undefined or weak symbol' check "an undefined external function is refused by the object check" refused

LINKONCE='#[linkage = "linkonce_odr"]
#[no_mangle]
pub extern "C" fn ebpf_panic_reached() -> ! { loop {} }'
SAVED_EXTERN="$EXTERN"
EXTERN=""
LINKAGE_REFUSAL='linkage. is not in the list of allowed features'
linkonce_attack() {
  CRATE_ATTRS="$1"
  write_crate 'let table = [1u32, 2, 3, 4]; table[n]' "$LINKONCE"
  REFUSAL_TEXT="$LINKAGE_REFUSAL" check "$2" refused_build
}
linkonce_attack '#![feature(linkage)]' "linkonce_odr crate with #![feature(linkage)] is refused by the build"
linkonce_attack '#![cfg_attr(
    all(target_arch = "bpf", target_endian = "little"),
    feature(linkage)
)]' "linkonce_odr behind a multi-line cfg_attr is refused by the build"
linkonce_attack '#![doc = "]"]
#![feature(linkage)]' "linkonce_odr after a doc attribute holding a bracket is refused by the build"
EXTERN="$SAVED_EXTERN"
CRATE_ATTRS=""

write_crate 'value ^ n as u32'
printf '\n[[bin]]\nname = "ebpf-probes-kernel"\npath = "%s/outside.rs"\n' "$ROOT/target" >>"$SCRATCH/Cargo.toml"
printf '#![no_std]\n#![no_main]\n#![feature(linkage)]\nuse aya_ebpf as _;\n#[panic_handler]\nfn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }\n' >"$ROOT/target/outside.rs"
REFUSAL_TEXT="$LINKAGE_REFUSAL" check "a [[bin]] path outside the manifest directory with #![feature(linkage)] is refused by the build" refused_build

write_crate 'value ^ n as u32'
printf '#![no_std]\n#![no_main]\n#![feature(linkage)]\nuse aya_ebpf as _;\n#[panic_handler]\nfn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }\n' >"$SCRATCH/real.rs"
rm "$SCRATCH/src/main.rs"
ln -s ../real.rs "$SCRATCH/src/main.rs"
REFUSAL_TEXT="$LINKAGE_REFUSAL" check "a symlinked src/main.rs with #![feature(linkage)] is refused by the build" refused_build

DEP_MANIFEST_HEADER='cargo-features = ["test-dummy-unstable"]
'
write_crate 'value ^ n as u32' 'use panicdep as _;'
REFUSAL_TEXT='nightly version of Cargo|nightly-only|unstable' check "a path dependency with cargo-features is refused by the build" refused_build
DEP_MANIFEST_HEADER=""
write_crate 'panicdep::fine() ^ value' '' '#![no_std]
#![feature(linkage)]
pub fn fine() -> u32 { 1 }'
REFUSAL_TEXT="$LINKAGE_REFUSAL" check "a path dependency with #![feature(linkage)] is refused by the build" refused_build
write_crate 'value ^ n as u32'
passes() {
  build_object
  EBPF_NIGHTLY="$NIGHTLY" "$MUTATED" "$OBJECT" >/dev/null
}
check "a program without any panic path passes" passes

real_crate_passes() {
  EBPF_NIGHTLY="$NIGHTLY" EBPF_OFFLINE=1 "$BUILDER" "$KERNEL/Cargo.toml" "$BUILD_TARGET" >&2
  EBPF_NIGHTLY="$NIGHTLY" "$MUTATED" "$OBJECT"
}
check "the real kernel crate passes" real_crate_passes

BAD="$ROOT/target/ebpf-no-panic-bad"
rm -rf "$BAD"
mkdir -p "$BAD/directory"
: >"$BAD/empty"
echo "not an object" >"$BAD/text"
cp /bin/ls "$BAD/x86"
mkdir -p "$BAD/bin"
ln -s "$(rustc "+$NIGHTLY" --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-readobj" "$BAD/bin/llvm-readobj"
printf '#!/bin/sh\nexit 1\n' >"$BAD/bin/llvm-nm"
chmod 755 "$BAD/bin/llvm-nm"

refused_by_name() {
  local path="$1" reason="$2" output
  if output=$(EBPF_NIGHTLY="$NIGHTLY" EBPF_LLVM_BIN="${3:-}" "$MUTATED" "$path" 2>&1); then
    echo "$output"
    return 1
  fi
  grep -qF "$reason" <<<"$output"
}

check "a missing object is refused by name" refused_by_name "$BAD/missing" "is missing"
check "a directory is refused by name" refused_by_name "$BAD/directory" "is not a regular file"
check "a zero-byte object is refused by name" refused_by_name "$BAD/empty" "is empty"
check "a text file is refused by name" refused_by_name "$BAD/text" "is not an ELF file"
check "an x86 ELF file is refused by name" refused_by_name "$BAD/x86" "is not a BPF ELF file"
check "an llvm-nm failure is refused by name" refused_by_name "$OBJECT" "llvm-nm failed" "$BAD/bin"
cp /bin/ls "$BAD/Machine: EM_BPF x86"
check "an x86 file whose path says Machine: EM_BPF is refused" refused_by_name "$BAD/Machine: EM_BPF x86" "is not a BPF ELF file"
mkdir -p "$BAD/nobin"
check "a missing llvm tool is named as a missing tool" refused_by_name "$OBJECT" "the tool llvm-readobj is missing" "$BAD/nobin"

prints_override() {
  local output
  output=$(EBPF_NIGHTLY="$NIGHTLY" EBPF_LLVM_BIN="$BAD/bin" "$MUTATED" "$OBJECT" 2>&1 || true)
  grep -qF "override EBPF_LLVM_BIN=$BAD/bin" <<<"$output"
}
check "an EBPF_LLVM_BIN override is announced" prints_override

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
