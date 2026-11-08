#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
export HOME="$SCRATCH/home"
mkdir -p "$HOME" "$SCRATCH/bin" "$SCRATCH/nobin"
cat >"$SCRATCH/bin/cargo" <<'S'
#!/usr/bin/env bash
echo "cargo wrapper=${RUSTC_WRAPPER:-none} dir=${SCCACHE_DIR:-none} size=${SCCACHE_CACHE_SIZE:-none} inc=${CARGO_INCREMENTAL}" >>"$STUB_LOG"
S
printf '#!/usr/bin/env bash\nexit 0\n' >"$SCRATCH/bin/sccache"
chmod +x "$SCRATCH/bin/"*
cp "$SCRATCH/bin/cargo" "$SCRATCH/nobin/"
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

: >"$STUB_LOG"
env PATH="$SCRATCH/bin:/usr/bin:/bin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if grep -qv "wrapper=sccache dir=$HOME/.cache/sccache size=20G inc=0" "$STUB_LOG"; then
  echo "FAIL: wrapper missing with sccache present"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi

: >"$STUB_LOG"
env PATH="$SCRATCH/nobin" "$HERE/.githooks/pre-commit" >/dev/null 2>&1
if grep -qv "wrapper=none dir=none size=none inc=0" "$STUB_LOG"; then
  echo "FAIL: wrapper set without sccache"
  cat "$STUB_LOG"
  FAILS=$((FAILS + 1))
fi
exit "$FAILS"
