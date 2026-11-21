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

readonly SKIPS=(
    "sys-windows|a_junction_in_the_path_is_refused_at_its_component|junctions cannot be created"
    "sys-windows|a_junction_at_an_entry_name_is_refused_as_a_reparse_point|junctions cannot be created"
    "sys-windows|a_protected_leaf_under_the_default_ancestors_is_accepted|C:\\ is user-owned and icacls is missing"
    "sys-windows|an_ancestor_the_user_controls_is_refused_by_name_before_the_spool_directory|C:\\ is user-owned and icacls is missing"
)

failed_total=0
for crate in "${crates[@]}"; do
    log="$LOG_DIR/$crate.log"
    skip_args=()
    skip_note=""
    stale=""
    for entry in "${SKIPS[@]}"; do
        IFS='|' read -r skip_crate skip_name skip_reason <<<"$entry"
        if [ "$skip_crate" = "$crate" ]; then
            skip_args+=(--skip "$skip_name")
            skip_note="$skip_note${skip_note:+; }$skip_name, $skip_reason"
            grep -rqE "fn $skip_name\(" "crates/$crate/tests" || stale="$stale $skip_name"
        fi
    done
    if [ -n "$stale" ]; then
        echo "$crate: failed (stale skip entry matching no test:$stale)"
        failed_total=$((failed_total + 1))
        continue
    fi
    timeout "$CRATE_TIMEOUT" cargo test --target "$TARGET" -p "$crate" -- "${skip_args[@]}" >"$log" 2>&1
    status=$?
    failing=$(grep -E '^test .* \.\.\. FAILED$' "$log" | sed 's/^test \(.*\) \.\.\. FAILED$/\1/' | tr '\n' ' ')
    if ! grep -q '^test result:' "$log"; then
        echo "$crate: not runnable (exit $status: $(grep -m1 -E '^(error|Error)|timed out' "$log" || echo "see $log"))"
        failed_total=$((failed_total + 1))
    elif [ "$status" -eq 0 ] && grep -q '^test result: ok' "$log" && ! grep -q '^test result: FAILED' "$log" && [ -z "$failing" ]; then
        if [ "${#skip_args[@]}" -gt 0 ]; then
            echo "$crate: passed ($((${#skip_args[@]} / 2)) skipped under Wine: $skip_note)"
        else
            echo "$crate: passed"
        fi
    else
        echo "$crate: failed (exit $status: $failing)"
        failed_total=$((failed_total + 1))
    fi
done
echo "windows-under-wine.sh: ${#crates[@]} crates, $failed_total not passed"
[ "$failed_total" -eq 0 ]
