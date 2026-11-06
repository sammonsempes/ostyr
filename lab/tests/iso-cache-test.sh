#!/usr/bin/env bash
# Usage: lab/tests/iso-cache-test.sh
# Checks the shared ISO cache of images/iso-cache.sh with a stub curl: reuse without download, corrupt file replaced once,
# killed download leaves no final file, concurrent fetches download once, legacy files are moved. No VM, no network.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly SLOW_SECONDS=3
readonly SETTLE_SECONDS=1
readonly HANG_SECONDS=30

failures=0
check() {
    local description="$1"
    shift
    if "$@"; then
        log "ok   $description"
    else
        log "FAIL $description"
        failures=$((failures + 1))
    fi
}

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
mkdir "$work_dir/bin"
printf 'pinned content\n' >"$work_dir/content"
content_sha="$(sha256sum "$work_dir/content" | cut -d' ' -f1)"
printf 'test\t%s\ttest.iso\t2026-11-06\thttp://example.invalid/test.iso\n' "$content_sha" >"$work_dir/pins.tsv"

cat >"$work_dir/bin/curl" <<'STUB'
#!/usr/bin/env bash
output=""
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--output" ]]; then
        output="$2"
    fi
    shift
done
echo call >>"$STUB_COUNT"
if [[ -n "${STUB_HANG:-}" ]]; then
    head -c 4 "$STUB_CONTENT" >"$output"
    sleep "$STUB_HANG"
fi
cat "${STUB_BAD:-$STUB_CONTENT}" >"$output"
STUB
chmod +x "$work_dir/bin/curl"

export STUB_COUNT="$work_dir/count" STUB_CONTENT="$work_dir/content"
export LAB_ISO_CACHE="$work_dir/cache" PINS_FILE="$work_dir/pins.tsv" LAB_LEGACY_ISO_CACHE="$work_dir/legacy"
source "$LAB_DIR/images/iso-cache.sh"
PATH="$work_dir/bin:$PATH"
cached="$LAB_ISO_CACHE/test.iso"

reset_count() {
    : >"$STUB_COUNT"
}

calls() {
    wc -l <"$STUB_COUNT" | tr -d ' '
}

fetch_ok() {
    (fetch_pinned test >/dev/null 2>&1)
}

fetch_fails_with_bad_download() {
    ! (STUB_BAD="$work_dir/bad" fetch_pinned test >/dev/null 2>&1)
}

reset_count
check "first fetch downloads once" fetch_ok
check "first fetch made one call" test "$(calls)" = 1
check "cached file has the pinned content" cmp -s "$cached" "$work_dir/content"
reset_count
check "second fetch succeeds" fetch_ok
check "second fetch makes no download" test "$(calls)" = 0

printf 'corrupt\n' >"$cached"
reset_count
check "corrupt cache is repaired" fetch_ok
check "corrupt cache downloaded exactly once" test "$(calls)" = 1
check "repaired file matches" cmp -s "$cached" "$work_dir/content"

rm -f "$cached"
printf 'wrong\n' >"$work_dir/bad"
reset_count
check "a download that mismatches the pin fails" fetch_fails_with_bad_download
check "a mismatching download leaves no final file" test ! -e "$cached"

reset_count
(STUB_HANG="$HANG_SECONDS" fetch_pinned test >/dev/null 2>&1) &
fetch_pid=$!
sleep "$SETTLE_SECONDS"
pkill -TERM -f "$work_dir/bin/curl" || log "stub curl already gone"
kill "$fetch_pid" 2>/dev/null || log "fetch already gone"
wait "$fetch_pid" 2>/dev/null || log "fetch killed"
check "a killed download leaves no final file" test ! -e "$cached"
check "a later fetch recovers" fetch_ok
check "recovered file matches" cmp -s "$cached" "$work_dir/content"

rm -f "$cached"
reset_count
(STUB_HANG="$SLOW_SECONDS" fetch_pinned test >/dev/null 2>&1) &
first_pid=$!
(STUB_HANG="$SLOW_SECONDS" fetch_pinned test >/dev/null 2>&1) &
second_pid=$!
check "first concurrent fetch succeeds" wait "$first_pid"
check "second concurrent fetch succeeds" wait "$second_pid"
check "concurrent fetches downloaded once" test "$(calls)" = 1
check "concurrent result matches" cmp -s "$cached" "$work_dir/content"

rm -f "$cached"
mkdir "$work_dir/legacy"
cp "$work_dir/content" "$work_dir/legacy/test.iso"
reset_count
check "fetch with a legacy file succeeds" fetch_ok
check "legacy file used without download" test "$(calls)" = 0
check "legacy file was moved, not copied" test ! -e "$work_dir/legacy/test.iso"

[[ "$failures" -eq 0 ]] || die "$failures check(s) failed"
log "all iso-cache checks passed"
