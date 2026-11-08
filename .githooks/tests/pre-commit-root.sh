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
mkdir -p "$HOME" "$SCRATCH/bin" "$SCRATCH/nobin"
cat >"$SCRATCH/bin/cargo" <<'S'
#!/usr/bin/env bash
echo "cargo $*" >>"$STUB_LOG"
[ -z "${STUB_FAIL:-}" ] || [[ " $* " != *" $STUB_FAIL "* ]]
S
cat >"$SCRATCH/bin/id" <<'S'
#!/usr/bin/env bash
echo "${STUB_UID:-1000}"
S
cat >"$SCRATCH/bin/setpriv" <<'S'
#!/usr/bin/env bash
echo "setpriv $*" >>"$STUB_LOG"
exec "${@:3}"
S
chmod +x "$SCRATCH/bin/"*
cp "$SCRATCH/bin/cargo" "$SCRATCH/nobin/"
for tool in bash env git dirname mkdir rm cksum cut realpath flock find; do
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
expect "clippy plain" '^cargo clippy'
expect "llvm-cov plain" '^cargo \+nightly llvm-cov'
if grep -qE '^(nice|ionice)' "$STUB_LOG"; then
  echo "FAIL: low priority wrapper used"
  FAILS=$((FAILS + 1))
fi
if grep -q '^setpriv' "$STUB_LOG"; then
  echo "FAIL: setpriv used for a non-root user"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
env STUB_UID=0 PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
expect "root clippy" '^setpriv --bounding-set -dac_override,-dac_read_search,-fowner cargo clippy'
expect "root llvm-cov" '^setpriv --bounding-set -dac_override,-dac_read_search,-fowner cargo \+nightly llvm-cov'
expect "root lint" '^setpriv .* cargo run --offline -q -p custom_lint'
expect "root gate" '^setpriv .* cargo run --offline -q -p coverage_gate'

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
