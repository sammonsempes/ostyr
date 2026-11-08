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
echo "cargo $* tdir=${CARGO_LLVM_COV_TARGET_DIR:-} bdir=${CARGO_LLVM_COV_BUILD_DIR:-} tmp=${TMPDIR:-} jobs=${CARGO_BUILD_JOBS:-}" >>"$STUB_LOG"
S
chmod +x "$SCRATCH/bin/cargo"
export STUB_LOG="$SCRATCH/log"
R="$SCRATCH/repo"
mkdir -p "$R"
cd "$R"
git init -q
echo x >f.rs
git add -A
FAILS=0

: >"$STUB_LOG"
env -u COVERAGE_EXPORT CARGO_TARGET_DIR="$R/target" PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "--output-path $R/target/gates/" "$STUB_LOG"; then
  echo "FAIL: export not under CARGO_TARGET_DIR"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi
if ! grep -qF -- "coverage_gate -- $R/target/gates/" "$STUB_LOG"; then
  echo "FAIL: gate not reading CARGO_TARGET_DIR export"
  FAILS=$((FAILS + 1))
fi
if [ ! -d "$R/target" ]; then
  echo "FAIL: wrong directory created"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
env -u COVERAGE_EXPORT -u CARGO_TARGET_DIR OSTYR_PRIVATE_TARGET=1 PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "--output-path target/coverage.json" "$STUB_LOG"; then
  echo "FAIL: default export moved"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi
if grep -q "tdir=[^ ]" "$STUB_LOG"; then
  echo "FAIL: private target got per-gate directories"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
env -u COVERAGE_EXPORT -u CARGO_TARGET_DIR -u OSTYR_PRIVATE_TARGET PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "tdir=$R/target/gates/" "$STUB_LOG" || ! grep -qF -- "bdir=$R/target/llvm-cov-target" "$STUB_LOG"; then
  echo "FAIL: default is not the shared directory with a per-gate llvm-cov target"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
env -u COVERAGE_EXPORT CARGO_TARGET_DIR="$R/target" OSTYR_PRIVATE_TARGET=1 PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "--output-path target/coverage.json" "$STUB_LOG"; then
  echo "FAIL: opt-out does not beat CARGO_TARGET_DIR"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
env -u COVERAGE_EXPORT -u CARGO_TARGET_DIR -u OSTYR_PRIVATE_TARGET PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "tmp=$R/target/gates/" "$STUB_LOG" || ! grep -qF -- "/tmp-" "$STUB_LOG"; then
  echo "FAIL: TMPDIR not under the gate directory"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
if env -u COVERAGE_EXPORT CARGO_TARGET_DIR="$SCRATCH/elsewhere" PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >"$SCRATCH/out" 2>&1; then
  echo "FAIL: foreign CARGO_TARGET_DIR accepted"
  FAILS=$((FAILS + 1))
fi
if ! grep -qF "is neither" "$SCRATCH/out" || [ -s "$STUB_LOG" ]; then
  echo "FAIL: foreign CARGO_TARGET_DIR not refused before cargo"
  FAILS=$((FAILS + 1))
fi

W="$SCRATCH/wt"
git -c user.name=t -c user.email=t@example.com commit -q -m init
git worktree add -q "$W" -b side
cd "$W"
echo y >g.rs
git add -A
: >"$STUB_LOG"
env -u COVERAGE_EXPORT -u CARGO_TARGET_DIR -u OSTYR_PRIVATE_TARGET PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "tdir=$R/target/gates/" "$STUB_LOG"; then
  echo "FAIL: linked worktree does not use the main checkout target"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi

exit "$FAILS"
