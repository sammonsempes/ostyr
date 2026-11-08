#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
export HOME="$SCRATCH/home"
mkdir -p "$HOME" "$SCRATCH/bin"
cat >"$SCRATCH/bin/cargo" <<'S'
#!/usr/bin/env bash
echo "cargo $*" >>"$STUB_LOG"
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
env -u COVERAGE_EXPORT CARGO_TARGET_DIR="$SCRATCH/shared" PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "--output-path $SCRATCH/shared/coverage.json" "$STUB_LOG"; then
  echo "FAIL: export not under CARGO_TARGET_DIR"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi
if ! grep -qF -- "coverage_gate -- $SCRATCH/shared/coverage.json" "$STUB_LOG"; then
  echo "FAIL: gate not reading CARGO_TARGET_DIR export"
  FAILS=$((FAILS + 1))
fi
if [ ! -d "$SCRATCH/shared" ] || [ -e "$R/target" ]; then
  echo "FAIL: wrong directory created"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
env -u COVERAGE_EXPORT -u CARGO_TARGET_DIR PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if ! grep -qF -- "--output-path target/coverage.json" "$STUB_LOG"; then
  echo "FAIL: default export moved"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi
exit "$FAILS"
