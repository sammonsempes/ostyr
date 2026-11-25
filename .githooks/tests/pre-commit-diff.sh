#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HOOK_UNDER_TEST="${HOOK_UNDER_TEST:-$HERE/.githooks/pre-commit}"
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
[[ " $* " != *" kernel-declared "* ]] || echo "${STUB_KERNEL:-absent}"
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
mkdir -p "$R/.githooks" "$R/lab"
cp "$HOOK_UNDER_TEST" "$R/.githooks/pre-commit"
cat >"$R/lab/ebpf-build.sh" <<'S'
#!/usr/bin/env bash
echo "ebpf-build $*" >>"$STUB_LOG"
S
chmod +x "$R/lab/ebpf-build.sh"
cd "$R"
R=$(pwd -P)
git init -q
for name in base leaf user; do
  mkdir -p "crates/$name/src"
  echo "fn a() {}" >"crates/$name/src/lib.rs"
done
mkdir -p crates/ebpf-probes/ebpf/src
echo "fn k() {}" >crates/ebpf-probes/ebpf/src/lib.rs
echo "[package]" >crates/ebpf-probes/ebpf/Cargo.toml
echo "[workspace]" >Cargo.toml
cat >"$STUB_METADATA" <<M
{
  "workspace_members": ["base 0.0.0", "leaf 0.0.0", "user 0.0.0"],
  "packages": [
    {"id": "base 0.0.0", "name": "base", "manifest_path": "$R/crates/base/Cargo.toml"},
    {"id": "leaf 0.0.0", "name": "leaf", "manifest_path": "$R/crates/leaf/Cargo.toml"},
    {"id": "user 0.0.0", "name": "user", "manifest_path": "$R/crates/user/Cargo.toml"}
  ],
  "resolve": {"nodes": [
    {"id": "base 0.0.0", "deps": []},
    {"id": "leaf 0.0.0", "deps": []},
    {"id": "user 0.0.0", "deps": [{"pkg": "base 0.0.0"}]}
  ]}
}
M
export GIT_CONFIG_COUNT=3 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=t GIT_CONFIG_KEY_1=user.email GIT_CONFIG_VALUE_1=t@example.com
export GIT_CONFIG_KEY_2=core.hooksPath GIT_CONFIG_VALUE_2=/dev/null
git add -A
git commit -q -m base
FAILS=0
OUT="$SCRATCH/out"

fail() {
  echo "FAIL: $1"
  cat "$OUT"
  FAILS=$((FAILS + 1))
}

run_hook() {
  : >"$STUB_LOG"
  RC=0
  env "$@" .githooks/pre-commit >"$OUT" 2>&1 || RC=$?
}

commit_change() {
  git add -A
  git commit -q --allow-empty -m "$1"
}

expect_out() {
  if ! grep -qF -- "$2" "$OUT"; then fail "$1: expected output containing: $2"; fi
}

expect_refused() {
  local label=$1
  shift
  run_hook "$@"
  if [ "$RC" -eq 0 ] || ! grep -q "refused" "$OUT" || [ -s "$STUB_LOG" ]; then fail "$label: expected a named refusal and no cargo call (rc=$RC)"; fi
}

diff_case() {
  local label=$1 want=$2 path base
  shift 2
  base=$(git rev-parse HEAD)
  for path in "$@"; do
    mkdir -p "$(dirname "$path")"
    echo "x" >>"$path"
  done
  commit_change "$label"
  run_hook "GATE_SCOPE=diff:$base"
  expect_out "$label" "${want//@BASE@/$base}"
}

diff_case "leaf only" "scope (diff @BASE@) 1 packages: leaf" crates/leaf/src/lib.rs
if ! grep -qE '^cargo clippy --offline -p leaf --all-targets' "$STUB_LOG"; then fail "leaf clippy is scoped"; fi
diff_case "base dependents" "scope (diff @BASE@) 2 packages: base user" crates/base/src/lib.rs
diff_case "lock" "scope full workspace (Cargo.lock changes the whole workspace)" Cargo.lock
diff_case "githooks" "scope full workspace (.githooks/x changes the whole workspace)" .githooks/x
diff_case "fixture" "scope full workspace (crates/leaf/tests/snap.json changes the whole workspace)" crates/leaf/tests/snap.json
diff_case "docs only" "documentation-only commit" crates/leaf/CL''AUDE.md
if grep -q '^cargo' "$STUB_LOG"; then fail "docs only runs no cargo"; fi
diff_case "kernel only" "kernel-only commit" crates/ebpf-probes/ebpf/src/lib.rs
diff_case "non-ascii kernel path" "kernel-only commit" "crates/ebpf-probes/ebpf/src/é.rs" $'crates/ebpf-probes/ebpf/src/a\tb.rs'
export STUB_KERNEL=declared
diff_case "kernel script" "kernel crate: fmt and clippy" lab/ebpf-build.sh
if ! grep -q '^ebpf-build ' "$STUB_LOG"; then fail "kernel_touched reads the diff"; fi
unset STUB_KERNEL

BASE=$(git rev-parse HEAD)
LONG=$(printf 'a%.0s' $(seq 1024))
expect_refused "dash base" GATE_SCOPE=diff:-x
expect_refused "empty base" GATE_SCOPE=diff:
expect_refused "range base" GATE_SCOPE=diff:HEAD..x
expect_refused "long base" "GATE_SCOPE=diff:$LONG"
expect_refused "unknown scope" GATE_SCOPE=bogus
expect_refused "space base" "GATE_SCOPE=diff:HEAD HEAD"
expect_refused "empty diff" "GATE_SCOPE=diff:$BASE"
git tag treetag "HEAD^{tree}"
expect_refused "tree tag" GATE_SCOPE=diff:treetag
OTHER=$(git commit-tree -m other "$(git hash-object -t tree /dev/null)")
expect_refused "non-ancestor" "GATE_SCOPE=diff:$OTHER"
echo dirty >>crates/leaf/src/lib.rs
expect_refused "dirty tree" "GATE_SCOPE=diff:HEAD~1"
git add -A
expect_refused "dirty index" "GATE_SCOPE=diff:HEAD~1"
git reset -q --hard
echo u >crates/leaf/src/untracked.rs
expect_refused "untracked" "GATE_SCOPE=diff:HEAD~1"
rm crates/leaf/src/untracked.rs
run_hook "GATE_SCOPE=diff:HEAD~1"
if [ "$RC" -ne 0 ]; then fail "clean tree control passes (rc=$RC)"; fi
exit "$FAILS"
