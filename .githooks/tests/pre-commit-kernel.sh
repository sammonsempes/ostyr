#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
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
  env "$@" PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >"$SCRATCH/out" 2>&1 || true
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
  if ! grep -qE '^cargo \+nightly-2026-11-08 clippy --offline --locked --release --target bpfel-unknown-none -Z build-std=core --manifest-path crates/ebpf-probes/ebpf/Cargo.toml -- -D warnings$' "$STUB_LOG"; then
    echo "FAIL: $label: no kernel clippy"
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

if [ "$FAILS" -ne 0 ]; then
  echo "pre-commit-kernel: $FAILS failures"
  exit 1
fi
echo "pre-commit-kernel: ok"
