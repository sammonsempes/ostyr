#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HOOK="${HOOK:-$HERE/.githooks/pre-commit}"
mkdir -p "${CARGO_TARGET_DIR:-$PWD/target}"
SCRATCH=$(mktemp -d -p "${CARGO_TARGET_DIR:-$PWD/target}")
mkdir -p "$SCRATCH/tmp"
export TMPDIR="$SCRATCH/tmp"
unset CARGO_TARGET_DIR
trap 'rm -rf "$SCRATCH"' EXIT
PATH="$HOME/.cargo/bin:$PATH" cargo build -q --offline --manifest-path "$HERE/Cargo.toml" -p coverage_gate --target-dir "$SCRATCH/gate-target"
export HOME="$SCRATCH/home"
mkdir -p "$HOME" "$SCRATCH/bin"
cat >"$SCRATCH/bin/cargo" <<'S'
#!/usr/bin/env bash
echo "cargo $*" >>"$STUB_LOG"
if [[ " $* " == *" clippy "* ]]; then
  previous=""
  clippy_dir=""
  for argument in "$@"; do
    if [ "$previous" = --target-dir ]; then clippy_dir=$argument; fi
    previous=$argument
  done
  if [ -n "$clippy_dir" ]; then
    echo "clippy-dir-entries $(find "$clippy_dir" -mindepth 1 2>/dev/null | wc -l)" >>"$STUB_LOG"
    mkdir -p "$clippy_dir"
    echo leftover >"$clippy_dir/built-by-clippy"
  fi
fi
[ -z "${STUB_FAIL:-}" ] || [[ " $* " != *" $STUB_FAIL "* ]]
S
chmod +x "$SCRATCH/bin/cargo"
cat >"$SCRATCH/bin/gate" <<S
#!/usr/bin/env bash
if [ "\$1" = kernel-declared ]; then exec "$SCRATCH/gate-target/debug/coverage_gate" "\$@"; fi
S
chmod +x "$SCRATCH/bin/gate"
cat >"$SCRATCH/bin/no-panic" <<'S'
#!/usr/bin/env bash
echo "no-panic $*" >>"$STUB_LOG"
S
chmod +x "$SCRATCH/bin/no-panic"
export EBPF_NO_PANIC="$SCRATCH/bin/no-panic"
export COVERAGE_GATE="$SCRATCH/bin/gate"
export STUB_LOG="$SCRATCH/log"
export COVERAGE_EXPORT="$SCRATCH/cov.json"
R="$SCRATCH/repo"
mkdir -p "$R"
cd "$R"
git init -q
FAILS=0

run_hook() {
  : >"$STUB_LOG"
  env "$@" PATH="$SCRATCH/bin:/usr/bin:/bin" "$HOOK" >"$SCRATCH/out" 2>&1 || true
}

stage() {
  git rm -q -r --cached . >/dev/null 2>&1 || true
  find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
  mkdir -p "$(dirname "$1")"
  echo x >"$1"
  git add -A
}

EXCLUDE_TOML=$'[workspace]\nexclude = ["crates/ebpf-probes/ebpf"]'

declare_kernel() {
  printf '%s\n' "$EXCLUDE_TOML" >Cargo.toml
  mkdir -p crates/ebpf-probes/ebpf
  echo x >crates/ebpf-probes/ebpf/Cargo.toml
  mkdir -p lab
  printf '#!/usr/bin/env bash\necho "no-panic $*" >>"$STUB_LOG"\n' >lab/ebpf-no-panic.sh
  chmod +x lab/ebpf-no-panic.sh
  cat >lab/ebpf-build.sh <<'B'
#!/usr/bin/env bash
if [ -n "${EBPF_CHECK_ONLY:-}" ]; then
  echo "check $*" >>"$STUB_LOG"
  [ "${STUB_FAIL:-}" != check ] || exit 1
  exit 0
fi
echo "build $*" >>"$STUB_LOG"
[ "${STUB_FAIL:-}" != build ] || exit 1
OUT="${STUB_OBJECT_ROOT:-$2}/bpfel-unknown-none/release/ebpf-probes-kernel"
mkdir -p "$(dirname "$OUT")"
echo object >"$OUT"
B
  chmod +x lab/ebpf-build.sh
  git add -A
}

expect_kernel() {
  local label=$1
  if ! grep -qE '^cargo \+nightly fmt --check --manifest-path crates/ebpf-probes/ebpf/Cargo.toml$' "$STUB_LOG"; then
    echo "FAIL: $label: no kernel fmt"
    FAILS=$((FAILS + 1))
  fi
  if ! grep -qxF "no-panic $R/target/bpfel-unknown-none/release/ebpf-probes-kernel" "$STUB_LOG"; then
    echo "FAIL: $label: the checker did not get the object the build writes under CARGO_TARGET_DIR"
    FAILS=$((FAILS + 1))
  fi
  if ! grep -qE '^cargo \+nightly-2026-11-08 clippy --offline --locked --release --target bpfel-unknown-none -Z build-std=core --manifest-path crates/ebpf-probes/ebpf/Cargo.toml --target-dir '"$R"'/target/ebpf-clippy -- -D warnings$' "$STUB_LOG"; then
    echo "FAIL: $label: no kernel clippy"
    FAILS=$((FAILS + 1))
  fi
  if [ "$(grep -n -m1 -E '^check ' "$STUB_LOG" | cut -d: -f1)" -ge "$(grep -n -m1 -E 'bpfel-unknown-none -Z build-std|fmt --check --manifest-path' "$STUB_LOG" | cut -d: -f1)" ]; then
    echo "FAIL: $label: the build refusals (ebpf-build.sh in check-only mode) did not run before every cargo command of the kernel step"
    FAILS=$((FAILS + 1))
  fi
  if ! grep -qxF "build crates/ebpf-probes/ebpf/Cargo.toml $R/target" "$STUB_LOG"; then
    echo "FAIL: $label: the release build did not go through lab/ebpf-build.sh with the manifest and the target directory"
    FAILS=$((FAILS + 1))
  fi
}

stage plain.rs
declare_kernel
git -c user.name=t -c user.email=t@t commit -q -m base
echo y >plain.rs
git add plain.rs
run_hook
if grep -q bpfel "$STUB_LOG"; then
  echo "FAIL: kernel step ran for an unrelated commit"
  FAILS=$((FAILS + 1))
fi

stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
run_hook
expect_kernel "kernel file staged"

stage .githooks/pre-commit
declare_kernel
run_hook
expect_kernel "hook staged"

stage lab/ebpf-no-panic.sh
declare_kernel
echo changed >>lab/ebpf-no-panic.sh
git add -A
run_hook
expect_kernel "panic check script staged"

stage lab/tests/ebpf-no-panic-test.sh
declare_kernel
run_hook
expect_kernel "panic check test staged"

stage lab/ebpf-build.sh
declare_kernel
echo "true" >>lab/ebpf-build.sh
git add -A
run_hook
expect_kernel "build script staged"

stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
mkdir -p target/ebpf-clippy/debug
echo stale >target/ebpf-clippy/debug/proc-macro-leftover
run_hook
if ! grep -qxF "clippy-dir-entries 0" "$STUB_LOG"; then
  echo "FAIL: the kernel clippy must start in an emptied target directory (a proc-macro built earlier from an edited source would run again on the host)"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi
if [ -e target/ebpf-clippy ]; then
  echo "FAIL: the clippy target directory must be removed after the clippy"
  FAILS=$((FAILS + 1))
fi
stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
run_hook STUB_FAIL=bpfel-unknown-none
if [ -e target/ebpf-clippy ]; then
  echo "FAIL: a failed clippy must still remove its target directory before the next run"
  FAILS=$((FAILS + 1))
fi
run_hook
if ! grep -qxF "clippy-dir-entries 0" "$STUB_LOG"; then
  echo "FAIL: the run after a failed clippy must start in an emptied directory"
  FAILS=$((FAILS + 1))
fi

stage plain.rs
declare_kernel
run_hook GATE_SCOPE=full
expect_kernel "full scope"

stage rustfmt.toml
declare_kernel
run_hook
expect_kernel "forced-full path rustfmt.toml"

stage Cargo.toml
declare_kernel
echo 'members = []' >>Cargo.toml
git add -A
run_hook
expect_kernel "forced-full path Cargo.toml"

stage "crates/ebpf-probes/ebpf/src/$(printf '\303\251').rs"
declare_kernel
run_hook
expect_kernel "non-ASCII kernel path"

stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
run_hook STUB_FAIL=bpfel-unknown-none
if ! grep -qF "FAILED at step: kernel crate" "$SCRATCH/out"; then
  echo "FAIL: failing kernel step not named"
  cat "$SCRATCH/out"
  FAILS=$((FAILS + 1))
fi

stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
run_hook STUB_OBJECT_ROOT="$SCRATCH/elsewhere"
if ! grep -qF "FAILED at step: kernel crate" "$SCRATCH/out" || ! grep -qF "the kernel build did not write" "$SCRATCH/out" || grep -q '^no-panic' "$STUB_LOG"; then
  echo "FAIL: a build that writes the object elsewhere must fail the hook before the check"
  FAILS=$((FAILS + 1))
fi

stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
mkdir -p target/bpfel-unknown-none/release
echo stale >target/bpfel-unknown-none/release/ebpf-probes-kernel
run_hook STUB_OBJECT_ROOT="$SCRATCH/elsewhere" STUB_FAIL=build
if ! grep -qF "FAILED at step: kernel crate" "$SCRATCH/out" || grep -q '^no-panic' "$STUB_LOG"; then
  echo "FAIL: a stale object left by an earlier build must never reach the check"
  FAILS=$((FAILS + 1))
fi

stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
run_hook STUB_FAIL=check
if ! grep -qF "FAILED at step: kernel crate" "$SCRATCH/out" || grep -qE '^(build|no-panic)|bpfel-unknown-none|manifest-path' "$STUB_LOG"; then
  echo "FAIL: a refusal of the check-only mode must stop the hook before clippy, fmt and the build (host code such as a build.rs would run there)"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi

stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
run_hook STUB_FAIL=fmt
if ! grep -qF "FAILED at step" "$SCRATCH/out"; then
  echo "FAIL: failing fmt not reported"
  FAILS=$((FAILS + 1))
fi

stage crates/ebpf-probes/ebpf/src/main.rs
printf '%s\n' "$EXCLUDE_TOML" >Cargo.toml
git add -A
run_hook
if ! grep -qF "crates/ebpf-probes/ebpf/Cargo.toml is missing" "$SCRATCH/out" || grep -q bpfel "$SCRATCH/log"; then
  echo "FAIL: missing kernel manifest not refused by name"
  FAILS=$((FAILS + 1))
fi
if ! grep -qF "FAILED at step: kernel crate" "$SCRATCH/out"; then
  echo "FAIL: missing kernel manifest did not fail the step"
  FAILS=$((FAILS + 1))
fi

stage .githooks/pre-commit
run_hook
if grep -q bpfel "$STUB_LOG" || ! grep -qF "kernel crate step skipped" "$SCRATCH/out" || grep -qF "FAILED" "$SCRATCH/out"; then
  echo "FAIL: repository without the exclude entry must skip and say so"
  FAILS=$((FAILS + 1))
fi

declare_kernel
rm -f Cargo.toml
git add -A
run_hook
if grep -q bpfel "$STUB_LOG" || ! grep -qF "would escape the gate" "$SCRATCH/out" || ! grep -qF "FAILED at step: kernel crate: declaration" "$SCRATCH/out"; then
  echo "FAIL: kernel manifest with no root manifest must fail by name"
  FAILS=$((FAILS + 1))
fi

stage plain.rs
declare_kernel
printf '[workspace]\nmembers = []\n' >Cargo.toml
git add -A
run_hook
if grep -q bpfel "$STUB_LOG" || ! grep -qF "would escape the gate" "$SCRATCH/out" || ! grep -qF "FAILED at step: kernel crate: declaration" "$SCRATCH/out"; then
  echo "FAIL: kernel manifest with the exclude entry removed must fail by name"
  FAILS=$((FAILS + 1))
fi

stage plain.rs
printf '[workspace]\nmembers = []\n' >Cargo.toml
git add -A
run_hook
if grep -q bpfel "$STUB_LOG" || ! grep -qF "kernel crate step skipped" "$SCRATCH/out" || grep -qF "FAILED" "$SCRATCH/out"; then
  echo "FAIL: no kernel crate and no entry must skip and say so"
  FAILS=$((FAILS + 1))
fi

for spelling in "'crates/ebpf-probes/ebpf/'" '"crates/ebpf-probes/ebpf/"' '"crates/ebpf-probes//ebpf"' '"./crates/ebpf-probes/ebpf"'; do
  stage crates/ebpf-probes/ebpf/src/main.rs
  declare_kernel
  printf '[workspace]\nexclude = [%s]\n' "$spelling" >Cargo.toml
  git add -A
  run_hook
  if grep -q bpfel "$STUB_LOG" || grep -qF "skipped" "$SCRATCH/out" || ! grep -qF "FAILED at step: kernel crate: declaration" "$SCRATCH/out"; then
    echo "FAIL: respelled exclude entry $spelling must be refused, never skipped"
    FAILS=$((FAILS + 1))
  fi
done

stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
printf '[workspace]\nexclude = ['"'"'crates/ebpf-probes/ebpf'"'"']\n' >Cargo.toml
git add -A
run_hook
expect_kernel "single-quoted exact entry"

stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
git -c user.name=t -c user.email=t@t commit -q -m kernel-base
echo changed >crates/ebpf-probes/ebpf/src/main.rs
git add crates/ebpf-probes/ebpf/src/main.rs
run_hook
expect_kernel "kernel file only staged"
if grep -qE 'llvm-cov|^cargo clippy|^cargo \+nightly fmt --check$' "$STUB_LOG" || ! grep -qF "kernel-only commit" "$SCRATCH/out" || grep -qF "FAILED" "$SCRATCH/out"; then
  echo "FAIL: a kernel-only commit must run the kernel steps and skip the workspace steps (no coverage data for the kernel crate)"
  cat "$SCRATCH/out"
  FAILS=$((FAILS + 1))
fi

echo changed-again >crates/ebpf-probes/ebpf/src/main.rs
echo y >plain.rs
git add crates/ebpf-probes/ebpf/src/main.rs plain.rs
run_hook
if ! grep -q 'llvm-cov' "$STUB_LOG"; then
  echo "FAIL: a kernel file staged with another file must still run the workspace steps"
  FAILS=$((FAILS + 1))
fi

echo x >crates/ebpf-probes/ebpf/src/main.rs
git add crates/ebpf-probes/ebpf/src/main.rs
mkdir -p other
echo x >other/file.rs
git add other/file.rs
git -c user.name=t -c user.email=t@t commit -q -m other-base
rm other/file.rs
ln -s ../plain.rs other/file.rs
echo changed-three >crates/ebpf-probes/ebpf/src/main.rs
git add crates/ebpf-probes/ebpf/src/main.rs other/file.rs
run_hook
if ! grep -q 'llvm-cov' "$STUB_LOG" || grep -qF "kernel-only commit" "$SCRATCH/out"; then
  echo "FAIL: a type change (T) in another path beside a kernel file must take the full path"
  FAILS=$((FAILS + 1))
fi
git reset -q
git checkout -q -- other/file.rs crates/ebpf-probes/ebpf/src/main.rs

rm crates/ebpf-probes/ebpf/src/main.rs
ln -s ../../../../plain.rs crates/ebpf-probes/ebpf/src/main.rs
git add crates/ebpf-probes/ebpf/src/main.rs
run_hook
if ! grep -q 'llvm-cov' "$STUB_LOG" || grep -qF "kernel-only commit" "$SCRATCH/out"; then
  echo "FAIL: a kernel src file turned into a symlink must not take the kernel-only path"
  FAILS=$((FAILS + 1))
fi
git reset -q
git checkout -q -- crates/ebpf-probes/ebpf/src/main.rs

echo changed-four >crates/ebpf-probes/ebpf/src/extra.rs
git add crates/ebpf-probes/ebpf/src/extra.rs
run_hook
if grep -q 'llvm-cov' "$STUB_LOG" || ! grep -qF "kernel-only commit" "$SCRATCH/out"; then
  echo "FAIL: an added kernel src file alone must take the kernel-only path"
  FAILS=$((FAILS + 1))
fi
git reset -q
rm -f crates/ebpf-probes/ebpf/src/extra.rs

git reset -q
printf '[submodule "sub"]\n\tpath = sub\n\turl = ./x\n\tignore = all\n' >.gitmodules
git add .gitmodules
git update-index --add --cacheinfo 160000,1111111111111111111111111111111111111111,sub
git -c user.name=t -c user.email=t@t commit -q -m gitlink-base
echo changed-five >crates/ebpf-probes/ebpf/src/main.rs
git add crates/ebpf-probes/ebpf/src/main.rs
git update-index --cacheinfo 160000,2222222222222222222222222222222222222222,sub
run_hook
if ! grep -q 'llvm-cov' "$STUB_LOG" || grep -qF "kernel-only commit" "$SCRATCH/out"; then
  echo "FAIL: a gitlink hidden by ignore = all beside a kernel file must take the full path"
  FAILS=$((FAILS + 1))
fi
git reset -q
git checkout -q -- crates/ebpf-probes/ebpf/src/main.rs

run_hook EBPF_NO_PANIC="$SCRATCH/bin/no-panic"
if ! grep -qF "override EBPF_NO_PANIC=$SCRATCH/bin/no-panic" "$SCRATCH/out"; then
  echo "FAIL: an EBPF_NO_PANIC override must be announced"
  FAILS=$((FAILS + 1))
fi

cargo_config_refused() {
  local label=$1
  if ! grep -qF "$R/.cargo exists" "$SCRATCH/out" || [ -s "$STUB_LOG" ] || [ -e "$SCRATCH/runner-marker" ]; then
    echo "FAIL: $label: a repository .cargo must be refused by name before any cargo command"
    cat "$SCRATCH/out" "$STUB_LOG"
    FAILS=$((FAILS + 1))
  fi
}

plant_cargo_config() {
  mkdir -p .cargo
  printf '[build]\nrunner = "touch %s/runner-marker"\n' "$SCRATCH" >.cargo/config.toml
}

stage plain.rs
plant_cargo_config
run_hook
cargo_config_refused "an untracked root .cargo on a workspace commit"
stage crates/ebpf-probes/ebpf/src/main.rs
declare_kernel
plant_cargo_config
run_hook
cargo_config_refused "an untracked root .cargo on a kernel-only commit"
stage notes.md
plant_cargo_config
run_hook
cargo_config_refused "an untracked root .cargo on a documentation-only commit"
run_hook GATE_SCOPE=full
cargo_config_refused "an untracked root .cargo with GATE_SCOPE=full"
rm -rf .cargo
ln -s nowhere .cargo
run_hook
cargo_config_refused "a dangling .cargo symlink"
rm -f .cargo

ancestor_refused() {
  local label=$1 where=$2
  if ! grep -qF "$where/.cargo exists above the checkout" "$SCRATCH/out" || [ -s "$STUB_LOG" ] || [ -e "$SCRATCH/runner-marker" ]; then
    echo "FAIL: $label: a .cargo above a linked worktree must be refused by name before any cargo command"
    cat "$SCRATCH/out" "$STUB_LOG"
    FAILS=$((FAILS + 1))
  fi
}

stage plain.rs
declare_kernel
git -c user.name=t -c user.email=t@t commit -q -m worktree-base
WT="$R/wt-parent/mid/wt"
mkdir -p "$R/wt-parent"
git worktree add -q --detach "$WT" HEAD
cd "$WT"
echo z >plain.rs
git add plain.rs
run_hook
if grep -qF "exists above the checkout" "$SCRATCH/out" || [ ! -s "$STUB_LOG" ]; then
  echo "FAIL: a linked worktree with no .cargo above it must run the gate (control for the refusal tests)"
  FAILS=$((FAILS + 1))
fi
for above in "$R" "$R/wt-parent" "$R/wt-parent/mid"; do
  mkdir -p "$above/.cargo"
  printf '[build]\nrunner = "touch %s/runner-marker"\n' "$SCRATCH" >"$above/.cargo/config.toml"
  run_hook
  ancestor_refused "a .cargo in $above" "$above"
  rm -rf "$above/.cargo"
done
ln -s nowhere "$R/wt-parent/.cargo"
run_hook
ancestor_refused "a dangling .cargo symlink in $R/wt-parent" "$R/wt-parent"
rm -f "$R/wt-parent/.cargo"
cd "$R"

if [ "$FAILS" -ne 0 ]; then
  echo "pre-commit-kernel: $FAILS failures"
  exit 1
fi
echo "pre-commit-kernel: ok"
