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
for tool in cargo custom_lint; do
  printf '#!/usr/bin/env bash\nexit 0\n' >"$SCRATCH/bin/$tool"
  chmod +x "$SCRATCH/bin/$tool"
done
export PATH="$SCRATCH/bin:$PATH"
export CUSTOM_LINT="$SCRATCH/bin/custom_lint"
export COVERAGE_GATE="$SCRATCH/bin/custom_lint"
export COVERAGE_EXPORT="$SCRATCH/cov.json"
WORD_A="cl""aude"
WORD_B="Anthro""pic"
HIDDEN=".$WORD_A"
R="$SCRATCH/repo"
mkdir -p "$R/.githooks" "$R/$HIDDEN/publish"
cp "$HERE/.githooks/pre-commit" "$R/.githooks/pre-commit"
printf 'rewrite src/rewritten.txt %s\n' "'s/a/b/'" >"$R/$HIDDEN/publish/index-filter.sh"
cd "$R"
git init -q
git add -A
git -c core.hooksPath=/dev/null -c user.name=t -c user.email=t@example.com commit -q -m base
FAILS=0

check() {
  local label=$1 expect=$2 path=$3 text=$4 got=accepted
  mkdir -p "$(dirname "$path")"
  echo "$text" >>"$path"
  git add -A
  if ! git -c core.hooksPath=.githooks -c user.name=t -c user.email=t@example.com commit -q -m "$label" >"$SCRATCH/out" 2>&1; then got=refused; fi
  if [ "$got" = refused ] && ! grep -qF "$path is published" "$SCRATCH/out"; then got=refused-for-another-reason; fi
  if [ "$got" != "$expect" ]; then
    echo "FAIL: $label expected $expect got $got"
    cat "$SCRATCH/out"
    FAILS=$((FAILS + 1))
  fi
  git reset -q
  git clean -fdq
}

check "plain text" accepted src/a.txt "nothing here"
check "mention in source" refused src/b.txt "see $WORD_A"
check "mention upper case" refused src/c.txt "$(echo "$WORD_B" | tr a-z A-Z)"
check "rewritten path" accepted src/rewritten.txt "$WORD_A"
check "notes file" accepted "crates/a/$(echo "$WORD_A" | tr a-z A-Z).md" "$WORD_A"
check "private dir" accepted "$HIDDEN/x.json" "$WORD_A"
check "backlog" accepted backlog/t.md "$WORD_B"
exit "$FAILS"
