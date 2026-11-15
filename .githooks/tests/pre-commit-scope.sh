#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "${CARGO_TARGET_DIR:-$PWD/target}"
SCRATCH=$(mktemp -d -p "${CARGO_TARGET_DIR:-$PWD/target}")
mkdir -p "$SCRATCH/tmp"
export TMPDIR="$SCRATCH/tmp"
unset CARGO_TARGET_DIR
trap 'rm -rf "$SCRATCH"' EXIT
export HOME="$SCRATCH/home"
mkdir -p "$HOME" "$SCRATCH/bin"
cat >"$SCRATCH/bin/cargo" <<'S'
#!/usr/bin/env bash
echo "cargo $*" >>"$STUB_LOG"
if [ "${1:-}" = metadata ]; then cat "$STUB_METADATA"; fi
S
cat >"$SCRATCH/bin/tool" <<'S'
#!/usr/bin/env bash
echo "tool $*" >>"$STUB_LOG"
S
chmod +x "$SCRATCH/bin/cargo" "$SCRATCH/bin/tool"
export PATH="$SCRATCH/bin:$PATH"
export CUSTOM_LINT="$SCRATCH/bin/tool"
export COVERAGE_GATE="$SCRATCH/bin/tool"
export COVERAGE_EXPORT="$SCRATCH/cov.json"
export STUB_LOG="$SCRATCH/log"
export STUB_METADATA="$SCRATCH/metadata.json"
R="$SCRATCH/repo"
mkdir -p "$R/.githooks"
cp "$HERE/.githooks/pre-commit" "$R/.githooks/pre-commit"
cd "$R"
R=$(pwd -P)
git init -q
for name in base leaf user; do
  mkdir -p "crates/$name/src"
  echo "fn a() {}" >"crates/$name/src/lib.rs"
done
echo "[workspace]" >Cargo.toml
echo "doc" >README.txt
cat >"$STUB_METADATA" <<M
{
  "workspace_members": ["base 0.0.0", "leaf 0.0.0", "user 0.0.0"],
  "packages": [
    {"id": "base 0.0.0", "name": "base", "manifest_path": "$R/crates/base/Cargo.toml"},
    {"id": "leaf 0.0.0", "name": "leaf", "manifest_path": "$R/crates/leaf/Cargo.toml"},
    {"id": "user 0.0.0", "name": "user", "manifest_path": "$R/crates/user/Cargo.toml"},
    {"id": "outside 0.0.0", "name": "outside", "manifest_path": "/elsewhere/outside/Cargo.toml"}
  ],
  "resolve": {"nodes": [
    {"id": "base 0.0.0", "deps": [{"pkg": "outside 0.0.0"}]},
    {"id": "leaf 0.0.0", "deps": []},
    {"id": "user 0.0.0", "deps": [{"pkg": "base 0.0.0"}]},
    {"id": "outside 0.0.0", "deps": [{"pkg": "user 0.0.0"}]}
  ]}
}
M
git add -A
git -c core.hooksPath=/dev/null -c user.name=t -c user.email=t@example.com commit -q -m base
FAILS=0

check() {
  local label=$1 want=$2 env_scope=$3 path
  shift 3
  : >"$STUB_LOG"
  for path in "$@"; do
    echo "# line" >>"$path"
  done
  git add -A
  GATE_SCOPE=$env_scope git -c core.hooksPath=.githooks -c user.name=t -c user.email=t@example.com commit -q --allow-empty -m "$label" >"$SCRATCH/out" 2>&1 || true
  if ! grep -qF -- "$want" "$SCRATCH/out"; then
    echo "FAIL: $label expected scope line containing: $want"
    cat "$SCRATCH/out"
    FAILS=$((FAILS + 1))
  fi
}

expect_log() {
  local label=$1 pattern=$2
  if ! grep -qE -- "$pattern" "$STUB_LOG"; then
    echo "FAIL: $label expected a cargo call matching: $pattern"
    cat "$STUB_LOG"
    FAILS=$((FAILS + 1))
  fi
}

expect_no_log() {
  local label=$1 pattern=$2
  if grep -qE -- "$pattern" "$STUB_LOG"; then
    echo "FAIL: $label expected no call matching: $pattern"
    cat "$STUB_LOG"
    FAILS=$((FAILS + 1))
  fi
}

check "leaf only" "scope 1 packages: leaf" "" crates/leaf/src/lib.rs
expect_log "leaf fmt" '^cargo \+nightly fmt --check -p leaf$'
expect_log "leaf clippy" '^cargo clippy --offline -p leaf --all-targets -- -D warnings$'
expect_log "leaf coverage" '^cargo \+nightly llvm-cov --offline --branch -p leaf --fail-under-lines 100'
expect_log "leaf gate" '^tool .*cov.json .* crates/leaf$'
expect_no_log "leaf only" '-p (base|user)'

check "base and its dependents" "scope 2 packages: base user" "" crates/base/src/lib.rs
expect_log "base fmt" '^cargo \+nightly fmt --check -p base -p user$'
expect_log "base gate" '^tool .*cov.json .* crates/base crates/user$'

check "dependent only" "scope 1 packages: user" "" crates/user/src/lib.rs
check "root manifest" "scope full workspace (Cargo.toml changes the whole workspace)" "" Cargo.toml
expect_no_log "root manifest" ' -p '
expect_log "root gate" '^tool .*cov.json [^ ]*$'
check "member manifest" "scope full workspace (crates/leaf/Cargo.toml changes the whole workspace)" "" crates/leaf/Cargo.toml
mkdir -p crates/leaf/tests
echo '{}' >crates/leaf/tests/snap.json
git add -A
git -c core.hooksPath=/dev/null -c user.name=t -c user.email=t@example.com commit -q -m snap
check "package fixture" "scope full workspace (crates/leaf/tests/snap.json changes the whole workspace)" "" crates/leaf/tests/snap.json
check "empty staged set" "scope full workspace (no staged path)" ""
check "forced full" "scope full workspace (GATE_SCOPE=full)" full crates/leaf/src/lib.rs
expect_no_log "forced full" ' -p '
check "outside every package" "scope full workspace (README.txt is outside every package)" "" README.txt
check "outside plus package" "scope full workspace (README.txt is outside every package)" "" README.txt crates/leaf/src/lib.rs
check "hook itself" "scope full workspace (.githooks/pre-commit changes the whole workspace)" "" .githooks/pre-commit
check "docs only" "documentation-only commit" "" crates/leaf/CL''AUDE.md
expect_no_log "docs only" '^cargo'
: >"$STUB_METADATA"
check "no metadata" "scope full workspace (no cargo metadata)" "" crates/leaf/src/lib.rs
exit "$FAILS"
