#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export PATH="$HOME/.cargo/bin:$PATH"
cd "$HERE"
cargo build -q -p custom_lint -p coverage_gate
export CUSTOM_LINT="${CARGO_TARGET_DIR:-$HERE/target}/debug/custom_lint"
export COVERAGE_GATE="${CARGO_TARGET_DIR:-$HERE/target}/debug/coverage_gate"
mkdir -p "${CARGO_TARGET_DIR:-$PWD/target}"
SCRATCH=$(mktemp -d -p "${CARGO_TARGET_DIR:-$PWD/target}")
mkdir -p "$SCRATCH/tmp"
export TMPDIR="$SCRATCH/tmp"
unset CARGO_TARGET_DIR
trap 'rm -rf "$SCRATCH"' EXIT
export CARGO_TARGET_DIR="$SCRATCH/repo/target"
export COVERAGE_EXPORT="$SCRATCH/coverage.json"
FAILS=0

R="$SCRATCH/repo"
mkdir -p "$R/.githooks" "$R/crates/demo/src" "$R/crates/demo/tests" "$R/tools"
cp "$HERE/.githooks/pre-commit" "$R/.githooks/pre-commit"
cp "$HERE/rustfmt.toml" "$HERE/rust-toolchain.toml" "$R/"
printf '[workspace]\nmembers = ["crates/*"]\nresolver = "2"\n' >"$R/Cargo.toml"
printf '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n' >"$R/crates/demo/Cargo.toml"
printf 'target/\n' >"$R/.gitignore"
cat >"$R/crates/demo/tests/demo.rs" <<'T'
const TWO: u32 = 2;


#[test]
fn adds() -> Result<(), String> {
    assert_eq!(demo::add(1, 1), TWO);
    assert_eq!(demo::pick(true), 1);
    assert_eq!(demo::pick(false), 0);
    assert_eq!(demo::extra(true), 1);
    assert_eq!(demo::extra(false), 0);
    Ok(())
}
T

CLEAN_ADD='pub fn add(left: u32, right: u32) -> u32 {
    left + right
}
'
CLEAN_PICK='pub fn pick(flag: bool) -> u32 {
    if flag {
        1
    } else {
        0
    }
}
'
CLEAN_EXTRA='pub fn extra(flag: bool) -> u32 {
    if flag {
        1
    } else {
        0
    }
}
'
GAP='

'
cd "$R"
git init -q
(cd "$R" && cargo generate-lockfile --offline -q)

try() {
  local label=$1 expect=$2 failed_step=${3:-} got
  git add -A
  if git -c core.hooksPath="${HOOKS:-.githooks}" -c user.name=t -c user.email=t@example.com commit -q -m "$label" >"$SCRATCH/out.txt" 2>&1; then
    got=accepted
  else
    got=refused
  fi
  if [ -n "$failed_step" ] && ! grep -qF "FAILED at step: $failed_step" "$SCRATCH/out.txt"; then
    got="refused-elsewhere"
  fi
  if [ "$got" != "$expect" ]; then
    echo "FAIL: $label expected $expect got $got"
    tail -n 20 "$SCRATCH/out.txt"
    FAILS=$((FAILS + 1))
    exit 1
  fi
}

printf '%s' "pub fn add(left:u32,right:u32)->u32{left+right}$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA" >crates/demo/src/lib.rs
try "bad format" refused "1/5 cargo +nightly fmt --check"

printf '%s' "pub fn add(left: u32, right: u32) -> u32 {
    let unused = 1;
    left + right
}$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA" >crates/demo/src/lib.rs
try "clippy error" refused "2/5 cargo clippy"

printf '%s' "// a comment
$CLEAN_ADD$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA" >crates/demo/src/lib.rs
try "lint violation" refused "3/5 custom_lint"

printf '%s' "$CLEAN_ADD$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA$GAP${CLEAN_EXTRA/extra/untested}" >crates/demo/src/lib.rs
try "uncovered branch" refused "4/5 cargo llvm-cov"

printf '%s' "$CLEAN_ADD$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA" >crates/demo/src/lib.rs
try "clean commit" accepted

W="$SCRATCH/wt"
MAIN_HOOKS="$R/.githooks"
git worktree add -q "$W" -b side
printf '%s' "// a comment
$CLEAN_ADD$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA" >"$W/crates/demo/src/lib.rs"
mkdir -p "$W/tools"
cd "$W"
HOOKS="$MAIN_HOOKS" try "worktree violation" refused "3/5 custom_lint"
if git log --format=%s | grep -qx "worktree violation"; then
  echo "FAIL: worktree violation reached history"
  FAILS=$((FAILS + 1))
  exit 1
fi
printf '%s' "// a comment
$CLEAN_ADD$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA" >"$R/crates/demo/src/lib.rs"
printf '%s' "$CLEAN_ADD$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA" >"$W/crates/demo/src/lib.rs"
printf 'x\n' >"$W/note.txt"
HOOKS="$MAIN_HOOKS" try "worktree clean" accepted
printf 'y\n' >"$W/note.txt"
git add -A
if ! env PATH="/usr/bin:/bin" "$MAIN_HOOKS/pre-commit" >"$SCRATCH/out.txt" 2>&1; then
  echo "FAIL: hook without cargo on PATH"
  tail -n 20 "$SCRATCH/out.txt"
  FAILS=$((FAILS + 1))
  exit 1
fi
cd "$R"
git checkout -q -- .
git log -1 --format=%s >/dev/null

BASE_BRANCH=$(git symbolic-ref --short HEAD)
git checkout -q -b prototype/x
printf '%s' "$CLEAN_ADD$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA$GAP${CLEAN_EXTRA/extra/untested}" >crates/demo/src/lib.rs
try "prototype gap" accepted
if ! grep -qF "LIGHT GATE (prototype branch): coverage not checked" "$SCRATCH/out.txt"; then
  echo "FAIL: light gate line missing"
  FAILS=$((FAILS + 1))
  exit 1
fi
printf '%s' "pub fn add(left:u32,right:u32)->u32{left+right}$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA" >crates/demo/src/lib.rs
try "prototype bad format" refused "1/4 cargo +nightly fmt --check"
printf '%s' "pub fn add(left: u32, right: u32) -> u32 {
    let unused = 1;
    left + right
}$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA" >crates/demo/src/lib.rs
try "prototype clippy error" refused "2/4 cargo clippy"
printf '%s' "// a comment
$CLEAN_ADD$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA" >crates/demo/src/lib.rs
try "prototype lint violation" refused "3/4 custom_lint"
git checkout -q HEAD -- .
git checkout -q "$BASE_BRANCH"
printf '%s' "$CLEAN_ADD$GAP$CLEAN_PICK$GAP$CLEAN_EXTRA$GAP${CLEAN_EXTRA/extra/untested}" >crates/demo/src/lib.rs
try "other branch gap" refused "4/5 cargo llvm-cov"
git checkout -q HEAD -- .

if [ "$(git log --format=%s)" != "clean commit" ]; then
  echo "FAIL: history is not only the clean commit"
  FAILS=$((FAILS + 1))
  exit 1
fi
if [ "$FAILS" -ne 0 ]; then exit 1; fi
echo "pre-commit tests passed"
