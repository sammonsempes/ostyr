#!/usr/bin/env bash
# Usage: lab/tests/windows-under-wine.sh [crate...]
# Runs cargo test for the Windows GNU target under Wine for every crate with Windows-specific code (or the crates given), one summary line each.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ROOT
readonly TARGET="x86_64-pc-windows-gnu"
readonly CRATE_TIMEOUT="${WINE_CRATE_TIMEOUT:-1500}"
readonly LOG_DIR="$ROOT/target/wine-logs"

export PATH="$HOME/.cargo/bin:$PATH"
export WINEPREFIX="${WINEPREFIX:-$ROOT/target/wine-prefix}"
export WINEDEBUG=-all
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine64

cd "$ROOT" || exit 1
mkdir -p "$LOG_DIR"

if ! command -v wine64 >/dev/null; then
    echo "windows-under-wine.sh: wine64 missing, run lab/setup-wine.sh" >&2
    exit 1
fi

if [ "$#" -gt 0 ]; then
    crates=("$@")
else
    mapfile -t crates < <(grep -rl 'cfg(windows)\|cfg(not(unix))\|target_os = "windows"' crates/*/src crates/*/tests | cut -d/ -f2 | sort -u)
fi

failed_total=0
for crate in "${crates[@]}"; do
    log="$LOG_DIR/$crate.log"
    timeout "$CRATE_TIMEOUT" cargo test --target "$TARGET" -p "$crate" >"$log" 2>&1
    status=$?
    if [ "$status" -eq 0 ]; then
        echo "$crate: passed"
    elif grep -q '^test .* FAILED$' "$log"; then
        echo "$crate: failed ($(grep '^test .* FAILED$' "$log" | sed 's/^test \(.*\) \.\.\. FAILED$/\1/' | tr '\n' ' '))"
        failed_total=$((failed_total + 1))
    else
        echo "$crate: not runnable (exit $status: $(grep -m1 -E '^(error|Error)|timed out' "$log" || echo "see $log"))"
        failed_total=$((failed_total + 1))
    fi
done
echo "windows-under-wine.sh: ${#crates[@]} crates, $failed_total not passed"
[ "$failed_total" -eq 0 ]
