#!/usr/bin/env bash
# Usage: lab/ebpf-build.sh <kernel crate Cargo.toml> <target dir>
#        EBPF_CHECK_ONLY=1 lab/ebpf-build.sh <kernel crate Cargo.toml>   (runs every refusal below and builds nothing: the hook runs it before
#        any cargo command that compiles kernel-crate code, since a path build.rs or proc-macro runs on the host at clippy time)
# The one recipe that builds the shipped kernel object (hook, ebpf workflow and lab test all call it); the object lands in
# <target dir>/bpfel-unknown-none/release/<package>. Two steps, so that the compiler can refuse nightly features without refusing its own:
# 1. the sysroot (core, compiler_builtins) is built with -Z build-std from a fixed trivial crate, with no feature allowlist (compiler_builtins
#    itself uses #![feature(linkage)]);
# 2. the kernel crate is built against that sysroot with no build-std, by the stable cargo (it refuses cargo-features and every nightly cargo
#    setting in any manifest of the build) driving the pinned nightly rustc, with -Zallow-features=$ALLOWED_FEATURES in rustc flags (it refuses
#    any other #![feature] in the kernel crate and in every dependency). Changing ALLOWED_FEATURES is an owner decision: aya-ebpf needs
#    asm_experimental_arch, nothing else, and linkage must never be listed (a linkonce_odr ebpf_panic_reached hides a panic path).
# Before both steps, cargo metadata (cargo's own resolution, no text scan) lists every package of the build: a path package (the kernel crate
# and any path dependency) must have no build script and no proc-macro target, and a registry package with either must be in ALLOWED_BUILD_CODE
# with its Cargo.lock checksum. Host code (build scripts, proc macros) is not reached by -Zallow-features, so this is what keeps it from
# emitting a linkonce_odr ebpf_panic_reached or a link-arg bitcode. Changing ALLOWED_BUILD_CODE is an owner decision.
# The metadata is not filtered by platform (a superset of what cargo builds: host-only dependencies of build scripts are listed too). A package from
# any source but crates.io, a [patch] or [replace] table in a path manifest, and a .cargo entry between the kernel manifest and the repository
# root are refused by name (threat model: the rules file of crates/ebpf-probes). The sources are read from Cargo.lock first, before cargo metadata
# (which would fetch a remote source), so the refusal never depends on the cargo cache of remote sources. Every registry package of the graph is
# then re-verified: the .crate file in the registry cache must hash to the Cargo.lock checksum and the extracted source cargo will compile must
# equal the archive (cargo itself never re-reads an extracted registry source).
# The kernel crate is built into a fresh target directory (cargo fingerprints a registry package by id, so a proc-macro built once from an edited
# source would otherwise be reused after the edit is reverted) and the finished <target>/bpfel-unknown-none replaces the old one.
# The scratch directory is under the checkout's target/ and removed on every exit. Cargo.lock is read from the directory
# cargo locate-project reports, and a missing one is refused by name.
set -euo pipefail
MANIFEST=$(realpath -m "${1:?usage: ebpf-build.sh <kernel crate Cargo.toml> <target dir>}")
TARGET_DIR=${2:-}
if [ -n "$TARGET_DIR" ]; then TARGET_DIR=$(realpath -m "$TARGET_DIR"); fi
if [ -z "${EBPF_CHECK_ONLY:-}" ] && [ -z "$TARGET_DIR" ]; then
  echo "usage: ebpf-build.sh <kernel crate Cargo.toml> <target dir>" >&2
  exit 1
fi
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
NIGHTLY=${EBPF_NIGHTLY:-nightly-2026-11-08}
ALLOWED_FEATURES=asm_experimental_arch
ALLOWED_BUILD_CODE=(
  "anyhow 1.0.104 330a5ed07fa54e4702c9d6c4174f74427fc0ef6e214bbd677ae50a5099946470"
  "aya-ebpf 0.3.0 7998c4bcc24fb07447fe3018679f7ee1402ac9f27771753bb8890fc17ed967f4"
  "aya-ebpf-bindings 0.3.0 1f524fa99b4f6a4304d6f69a8f2591a716bfe3d82ca6b21e56561c262b6777a4"
  "aya-ebpf-cty 0.4.0 8b5264d5e8093e23c4ec11bfddf9c5d29adb70bd22d0af684af65dd25616d517"
  "aya-ebpf-macros 0.4.0 4d4de6938af16fd321f0f9a9fa2a0ba6777bd2665b7b09d3ab68a40c1e592631"
  "camino 1.2.6 bbbad30e4b4c14a39e3cc8aed085a12a327257c316619c93581e017bc52be591"
  "libc 0.2.191 65cd87c9a6d60536580b316ad985726104730a5151c99845f2490428ef91240a"
  "proc-macro2 1.0.107 985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9"
  "quote 1.0.47 1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001"
  "rustversion 1.0.23 cf54715a573b99ac80df0bc206da022bcd442c974952c7b9720069370852e21f"
  "serde 1.0.229 4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba"
  "serde_core 1.0.229 67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48"
  "serde_derive 1.0.229 e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348"
  "serde_json 1.0.154 e7e9cc8b1b85264074fbcc02a88680c4096b1e47df8f739dceb03bf482f04bd6"
  "thiserror 2.0.21 09e52cb86a36cede5cb101bf8908837b3e4c6e5e59fe7fd85c23fb56200d189e"
  "thiserror-impl 2.0.21 fe5197923287db20a58125f0bc85c062f7f2c892de97b18c356f9efb14b28524"
  "zmij 1.0.23 29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b"
)
TARGET=bpfel-unknown-none
CRATES_IO="registry+https://github.com/rust-lang/crates.io-index"
MAX_DEPTH=64
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
mkdir -p "$ROOT/target"
WORK_DIR=$(mktemp -d -p "$ROOT/target")
trap 'rm -rf "$WORK_DIR"' EXIT
case "$(cargo --version)" in
  *nightly*) fail "the default cargo is a nightly: step 2 needs the stable cargo of rust-toolchain.toml, which refuses cargo-features" ;;
esac
NIGHTLY_SYSROOT=$(rustc "+$NIGHTLY" --print sysroot) || fail "rustc +$NIGHTLY is not installed"
NIGHTLY_RUSTC="$NIGHTLY_SYSROOT/bin/rustc"
[ -x "$NIGHTLY_RUSTC" ] || fail "$NIGHTLY_RUSTC is missing"

lock_checksum() {
  awk -v name="$1" -v version="$2" -v source="$4" '/^\[\[package\]\]/ { found_name = ""; found_version = ""; found_source = "" }
    /^name = / { gsub(/"/, "", $3); found_name = $3 }
    /^version = / { gsub(/"/, "", $3); found_version = $3 }
    /^source = / { gsub(/"/, "", $3); found_source = $3 }
    /^checksum = / { gsub(/"/, "", $3); if (found_name == name && found_version == version && found_source == source) print $3 }' "$3"
}

build_code_allowed() {
  local name="$1" version="$2" source="$3" lock="$4" checksum entry
  local allowed=1
  if [ "$source" = path ]; then
    allowed=1
  else
    checksum=$(lock_checksum "$name" "$version" "$lock" "$source")
    allowed=1
    for entry in "${ALLOWED_BUILD_CODE[@]}"; do
      if [ "$entry" = "$name $version $checksum" ] && [ -n "$checksum" ]; then allowed=0; fi
    done
  fi
  return "$allowed"
}

check_lock_sources() {
  local lock="$1" line
  local -a foreign
  [ -f "$lock" ] || fail "$lock is missing: the sources and checksums of the build cannot be checked (commit the Cargo.lock of the kernel crate)"
  mapfile -t foreign < <(python3 -I -c 'import sys, tomllib
with open(sys.argv[1], "rb") as handle:
    document = tomllib.load(handle)
for package in document.get("package", []):
    source = package.get("source")
    if source is not None and source != sys.argv[2]:
        print(package["name"], package["version"], source)' "$lock" "$CRATES_IO") || fail "cannot read $lock"
  for line in "${foreign[@]+"${foreign[@]}"}"; do
    fail "the package $line does not come from crates.io (remote sources and other registries are refused)"
  done
}

verify_registry_package() {
  local name="$1" version="$2" directory="$3" lock="$4" crate checksum scratch="$WORK_DIR/verify"
  local cache="${CARGO_HOME:-$HOME/.cargo}/registry/cache"
  checksum=$(lock_checksum "$name" "$version" "$lock" "$CRATES_IO")
  crate=$(find "$cache" -maxdepth 2 -name "$name-$version.crate" 2>/dev/null | head -1)
  [ -n "$crate" ] || fail "the archive of $name $version is not in the registry cache $cache: it cannot be re-verified"
  [ -n "$checksum" ] && [ "$(sha256sum "$crate" | cut -d' ' -f1)" = "$checksum" ] \
  || fail "the archive of $name $version in the registry cache does not match the Cargo.lock checksum"
  rm -rf "$scratch"
  mkdir -p "$scratch"
  tar -xzf "$crate" -C "$scratch" || fail "cannot unpack the archive of $name $version"
  diff -r --exclude=.cargo-ok "$scratch/$name-$version" "$directory" >/dev/null \
  || fail "the extracted source of $name $version ($directory) differs from its archive: the registry source was edited"
  rm -rf "$scratch"
}

check_cargo_directories() {
  local directory stop
  directory=$(dirname "$(realpath "$MANIFEST")")
  stop=$(dirname "$ROOT")
  case "$directory/" in
    "$ROOT"/*) ;;
    *) stop=/ ;;
  esac
  for _ in $(seq "$MAX_DEPTH"); do
    if [ "$directory" != "$stop" ] && [ "$directory" != / ]; then
      if [ -e "$directory/.cargo" ] || [ -L "$directory/.cargo" ]; then
        fail "$directory/.cargo exists: a cargo config in the repository can replace a source or a dependency"
      fi
      directory=$(dirname "$directory")
    fi
  done
}

check_patch_tables() {
  local manifest
  for manifest in "$@"; do
    python3 -I -c 'import sys, tomllib
with open(sys.argv[1], "rb") as handle:
    document = tomllib.load(handle)
sys.exit(1 if "patch" in document or "replace" in document else 0)' "$manifest" \
      || fail "$manifest holds a [patch] or [replace] table: it swaps the code of a locked package"
  done
}

check_build_code() {
  local metadata lock line name version source directory
  local -a packages foreign manifests registry
  lock="$(dirname "$(cargo locate-project --workspace --message-format plain --manifest-path "$MANIFEST")")/Cargo.lock" \
    || fail "cargo locate-project failed on $MANIFEST"
  check_lock_sources "$lock"
  metadata=$(RUSTC="$NIGHTLY_RUSTC" cargo metadata "${OFFLINE[@]}" "${LOCKED[@]}" --format-version 1 --manifest-path "$MANIFEST") \
    || fail "cargo metadata failed on $MANIFEST"
  mapfile -t foreign < <(jq -r --arg registry "$CRATES_IO" '(.resolve.nodes | map(.id)) as $ids | .packages[] | select(.id as $id | $ids | index($id))
    | select(.source != null and .source != $registry) | [.name, .version, .source] | join(" ")' <<<"$metadata") || fail "cannot read cargo metadata"
  for line in "${foreign[@]+"${foreign[@]}"}"; do
    fail "the package $line does not come from crates.io (git, other registries and source replacements are refused)"
  done
  mapfile -t manifests < <(jq -r '.workspace_root + "/Cargo.toml", (.packages[] | select(.source == null) | .manifest_path)' <<<"$metadata") \
    || fail "cannot read cargo metadata"
  check_patch_tables "${manifests[@]}"
  mapfile -t registry < <(jq -r --arg registry "$CRATES_IO" '(.resolve.nodes | map(.id)) as $ids | .packages[] | select(.id as $id | $ids | index($id))
    | select(.source == $registry) | [.name, .version, (.manifest_path | rtrimstr("/Cargo.toml"))] | join("\u001f")' <<<"$metadata") \
    || fail "cannot read cargo metadata"
  for line in "${registry[@]+"${registry[@]}"}"; do
    IFS="$UNIT_SEPARATOR" read -r name version directory <<<"$line"
    verify_registry_package "$name" "$version" "$directory" "$lock"
  done
  mapfile -t packages < <(jq -r '(.resolve.nodes | map(.id)) as $ids | .packages[] | select(.id as $id | $ids | index($id))
    | select(any(.targets[].kind[]; . == "custom-build" or . == "proc-macro")) | [.name, .version, (.source // "path")] | join(" ")' <<<"$metadata") \
    || fail "cannot read cargo metadata"
  for line in "${packages[@]+"${packages[@]}"}"; do
    read -r name version source <<<"$line"
    build_code_allowed "$name" "$version" "$source" "$lock" \
      || fail "the package $name $version ($source) has a build script or a proc-macro target and is not in ALLOWED_BUILD_CODE (a path package never is)"
  done
}

check_cargo_directories
check_build_code
if [ -n "${EBPF_CHECK_ONLY:-}" ]; then exit 0; fi

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

BUILD_DIR="$WORK_DIR/kernel-target"
FLAGS="-Clink-arg=--btf${UNIT_SEPARATOR}--sysroot=$SYSROOT_DIR/root${UNIT_SEPARATOR}-Zallow-features=$ALLOWED_FEATURES"
env -u RUSTFLAGS CARGO_ENCODED_RUSTFLAGS="$FLAGS" RUSTC="$NIGHTLY_RUSTC" cargo build "${OFFLINE[@]}" "${LOCKED[@]}" --release --target "$TARGET" \
  --manifest-path "$MANIFEST" --target-dir "$BUILD_DIR" >&2 || fail "the kernel crate build failed (a feature outside $ALLOWED_FEATURES, or a nightly cargo setting, is refused here)"
rm -rf "$TARGET_DIR/$TARGET"
mv "$BUILD_DIR/$TARGET" "$TARGET_DIR/$TARGET"
