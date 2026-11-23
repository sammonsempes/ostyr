#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HOOK_SOURCE="${HOOK_UNDER_TEST:-$HERE/.githooks/pre-commit}"
mkdir -p "${CARGO_TARGET_DIR:-$PWD/target}"
SCRATCH=$(mktemp -d -p "${CARGO_TARGET_DIR:-$PWD/target}")
mkdir -p "$SCRATCH/tmp"
export TMPDIR="$SCRATCH/tmp"
unset CARGO_TARGET_DIR
trap 'rm -rf "$SCRATCH"' EXIT
export HOME="$SCRATCH/home"
mkdir -p "$HOME" "$SCRATCH/bin"
for tool in cargo custom_lint; do
  printf '#!/usr/bin/env bash\n[[ " $* " != *" kernel-declared "* ]] || echo absent\nexit 0\n' >"$SCRATCH/bin/$tool"
  chmod +x "$SCRATCH/bin/$tool"
done
export PATH="$SCRATCH/bin:$PATH"
export CUSTOM_LINT="$SCRATCH/bin/custom_lint"
export COVERAGE_GATE="$SCRATCH/bin/custom_lint"
export COVERAGE_EXPORT="$SCRATCH/cov.json"
R="$SCRATCH/repo"
OLD="crates/a/migrations/a_0001.sql"
mkdir -p "$R/.githooks" "$R/crates/a/migrations"
cp "$HOOK_SOURCE" "$R/.githooks/pre-commit"
cd "$R"
git init -q
echo "create table a (id int);" >"$OLD"
echo base >README
git add -A
git -c core.hooksPath=/dev/null -c user.name=t -c user.email=t@example.com commit -q -m base
FAILS=0

check() {
  local label=$1 expect=$2 needle=$3 got=accepted
  git add -A
  if ! git -c core.hooksPath=.githooks -c user.name=t -c user.email=t@example.com commit -q -m "$label" >"$SCRATCH/out" 2>&1; then got=refused; fi
  if [ "$got" = refused ] && ! grep -qF -- "$needle" "$SCRATCH/out"; then got=refused-for-another-reason; fi
  if [ "$got" = accepted ] && ! grep -qF -- "$needle" "$SCRATCH/out"; then got=accepted-without-message; fi
  if [ "$got" != "$expect" ]; then
    echo "FAIL: $label expected $expect got $got"
    cat "$SCRATCH/out"
    FAILS=$((FAILS + 1))
  fi
  git reset -q --hard
}

echo "one" >>README
check "absent public/main warns and passes" accepted "WARNING public/main is absent"
git update-ref refs/remotes/public/main HEAD
echo "two" >>README
check "unchanged published migration passes" accepted "pre-commit"
echo "create table b (id int);" >crates/a/migrations/a_0002.sql
check "new migration passes" accepted "pre-commit"
echo "alter table a add column x int;" >>"$OLD"
check "edited published migration is refused by name" refused "$OLD is a published migration"
rm "$OLD"
check "deleted published migration is refused by name" refused "$OLD is a published migration"
echo "alter table a add column x int;" >>"$OLD"
git add -A
git -c core.hooksPath=/dev/null -c user.name=t -c user.email=t@example.com commit -q -m edited
echo "three" >>README
check "an edit committed earlier is still refused" refused "$OLD is a published migration"
git reset -q --hard HEAD~1
git worktree add -q "$SCRATCH/outside" -b outside
echo "four" >>"$SCRATCH/outside/README"
git -C "$SCRATCH/outside" add -A
if (cd "$SCRATCH/outside" && git -c core.hooksPath="$R/.githooks" -c user.name=t -c user.email=t@example.com commit -q -m outside >"$SCRATCH/out" 2>&1); then
  echo "FAIL: a worktree outside the main checkout was accepted"
  FAILS=$((FAILS + 1))
elif ! grep -qF "is outside the main checkout" "$SCRATCH/out"; then
  echo "FAIL: a worktree outside the main checkout was refused for another reason"
  cat "$SCRATCH/out"
  FAILS=$((FAILS + 1))
fi
exit "$FAILS"
