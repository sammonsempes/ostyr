#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
export HOME="$SCRATCH/home"
mkdir -p "$HOME" "$SCRATCH/bin" "$SCRATCH/nobin"
cat >"$SCRATCH/bin/cargo" <<'S'
#!/usr/bin/env bash
echo "cargo $*" >>"$STUB_LOG"
[ -z "${STUB_FAIL:-}" ] || [[ " $* " != *" $STUB_FAIL "* ]]
S
cat >"$SCRATCH/bin/nice" <<'S'
#!/usr/bin/env bash
echo "nice $*" >>"$STUB_LOG"
exec "${@:3}"
S
cat >"$SCRATCH/bin/ionice" <<'S'
#!/usr/bin/env bash
echo "ionice $*" >>"$STUB_LOG"
exec "${@:3}"
S
chmod +x "$SCRATCH/bin/"*
cp "$SCRATCH/bin/cargo" "$SCRATCH/bin/nice" "$SCRATCH/nobin/"
for tool in bash env git dirname mkdir rm cksum cut; do
  ln -s "$(command -v "$tool")" "$SCRATCH/nobin/$tool"
done
export STUB_LOG="$SCRATCH/log"
export COVERAGE_EXPORT="$SCRATCH/cov.json"
R="$SCRATCH/repo"
mkdir -p "$R"
cd "$R"
git init -q
echo x >f.rs
git add -A
FAILS=0

expect() {
  local label=$1 pattern=$2
  if ! grep -qE "$pattern" "$STUB_LOG"; then
    echo "FAIL: $label: no match for $pattern"
    cat "$STUB_LOG"
    FAILS=$((FAILS + 1))
  fi
}

: >"$STUB_LOG"
env PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
expect "clippy low" '^nice -n 10 ionice -c 3 cargo clippy'
expect "llvm-cov low" '^ionice -c 3 cargo \+nightly llvm-cov'
expect "build low" '^ionice -c 3 cargo run --offline -q -p custom_lint'
expect "gate low" '^ionice -c 3 cargo run --offline -q -p coverage_gate'

: >"$STUB_LOG"
env PATH="$SCRATCH/nobin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
expect "nice only" '^nice -n 10 cargo clippy'
if grep -q '^ionice' "$STUB_LOG"; then
  echo "FAIL: ionice used while absent"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
if env STUB_FAIL=clippy PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >"$SCRATCH/out" 2>&1; then
  echo "FAIL: failing step accepted"
  FAILS=$((FAILS + 1))
fi
if ! grep -qF "FAILED at step: 2/5 cargo clippy" "$SCRATCH/out"; then
  echo "FAIL: failing step not named"
  FAILS=$((FAILS + 1))
fi
exit "$FAILS"
