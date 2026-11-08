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
mkdir -p "$HOME" "$SCRATCH/bin" "$SCRATCH/sync"
cat >"$SCRATCH/bin/cargo" <<'S'
#!/usr/bin/env bash
if [ "$1" = "+nightly" ] && [ "$2" = "fmt" ]; then
  touch "$SYNC/here.$(basename "$PWD")"
  POLLS=0
  MAX_POLLS=600
  while [ "$(find "$SYNC" -name 'here.*' | wc -l)" -lt 2 ] && [ "$POLLS" -lt "$MAX_POLLS" ]; do
    sleep 0.1
    POLLS=$((POLLS + 1))
  done
  [ "$(find "$SYNC" -name 'here.*' | wc -l)" -ge 2 ]
fi
S
chmod +x "$SCRATCH/bin/cargo"
export SYNC="$SCRATCH/sync"
export COVERAGE_EXPORT="$SCRATCH/cov.json"
R="$SCRATCH/repo"
mkdir -p "$R"
cd "$R"
git init -q
echo x >f.rs
git add -A
git -c user.name=t -c user.email=t@example.com commit -q --no-verify -m init
git worktree add -q "$SCRATCH/one" -b one
git worktree add -q "$SCRATCH/two" -b two
FAILS=0
for name in one two; do
  (cd "$SCRATCH/$name" && echo y >"g-$name.rs" && git add -A)
done
(cd "$SCRATCH/one" && env PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >"$SCRATCH/out.one" 2>&1) &
FIRST=$!
(cd "$SCRATCH/two" && env PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >"$SCRATCH/out.two" 2>&1) &
SECOND=$!
wait "$FIRST" || FAILS=$((FAILS + 1))
wait "$SECOND" || FAILS=$((FAILS + 1))
if [ "$FAILS" -ne 0 ]; then
  echo "FAIL: two hooks did not run their Rust steps at once"
  cat "$SCRATCH/out.one" "$SCRATCH/out.two"
fi
exit "$FAILS"
