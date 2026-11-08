#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
export HOME="$SCRATCH/home"
mkdir -p "$HOME" "$SCRATCH/bin"
for tool in cargo custom_lint; do
  cat >"$SCRATCH/bin/$tool" <<'S'
#!/usr/bin/env bash
echo "$(basename "$0") $*" >>"$STUB_LOG"
S
  chmod +x "$SCRATCH/bin/$tool"
done
export PATH="$SCRATCH/bin:$PATH"
export CUSTOM_LINT="$SCRATCH/bin/custom_lint"
export COVERAGE_GATE="$SCRATCH/bin/custom_lint"
export COVERAGE_EXPORT="$SCRATCH/cov.json"
export STUB_LOG="$SCRATCH/log"
R="$SCRATCH/repo"
mkdir -p "$R/.githooks"
cp "$HERE/.githooks/pre-commit" "$R/.githooks/pre-commit"
cd "$R"
git init -q
git add -A
git -c core.hooksPath=/dev/null -c user.name=t -c user.email=t@example.com commit -q -m base
FAILS=0

check() {
  local label=$1 expect=$2 got=full path
  shift 2
  : >"$STUB_LOG"
  for path in "$@"; do
    mkdir -p "$(dirname "$path")"
    echo "line" >>"$path"
  done
  git add -A
  git -c core.hooksPath=.githooks -c user.name=t -c user.email=t@example.com commit -q --allow-empty -m "$label" >"$SCRATCH/out" 2>&1 || true
  if grep -qF "Rust steps skipped" "$SCRATCH/out"; then got=skip; fi
  if [ "$got" = skip ] && grep -q '^cargo' "$STUB_LOG"; then got=skip-but-cargo; fi
  if [ "$got" = full ] && ! grep -q '^cargo' "$STUB_LOG"; then got=full-but-no-cargo; fi
  if [ "$got" != "$expect" ]; then
    echo "FAIL: $label expected $expect got $got"
    cat "$SCRATCH/out"
    FAILS=$((FAILS + 1))
  fi
}

check "backlog only" skip backlog/x.md
check "backlog plus crate" full backlog/y.md crates/a/src/lib.rs
check "docs spec" full docs/spec.md
check "crate notes" full crates/a/NOTES.md
check "root markdown" skip NOTES.md
check "cache dir" skip .cache/z.json
git rm -q backlog/x.md
check "backlog deletion" skip
check "hook itself" full .githooks/pre-commit
check "empty staged set" full
exit "$FAILS"
