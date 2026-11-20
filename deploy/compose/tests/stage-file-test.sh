#!/usr/bin/env bash
# Usage: sudo stage-file-test.sh [path to init.sh]
# Loads only the stage_file, link_set, unlink_published and check_present functions of init.sh (the ancestor walk never runs) and checks the descriptor layer.
set -euo pipefail

init_source="$(readlink -f "${1:-$(dirname "${BASH_SOURCE[0]}")/../init.sh}")"
work="$(mktemp -d)"
readonly init_source work
trap 'rm -rf "$work"' EXIT
chmod 0700 "$work"
failures=0

check() {
    if [[ "$2" == "$3" ]]; then
        printf 'ok: %s\n' "$1"
    else
        printf 'FAIL: %s (got %s, want %s)\n' "$1" "$2" "$3" >&2
        failures=$((failures + 1))
    fi
}

for function_name in stage_file link_set unlink_published check_present expected_owner expected_mode is_present; do
    sed -n "/^${function_name}() {/,/^}/p" "$init_source" >>"$work/functions.sh"
done
readonly SERVICE_UID=65532
readonly TLS_FILES=(a b)
export LC_ALL=C
source "$work/functions.sh"
check "test list of names" "${TLS_FILES[*]}" "a b"

reset() {
    rm -rf "$work/scratch" "$work/secrets" "$work/decoy" "$work/original" "$work/second-name"
    mkdir "$work/scratch" "$work/secrets"
    SECRETS_DIR="$work/secrets"
    scratch="$work/scratch"
    declare -gA staged_inode=()
    linked_names=()
    for name in a b; do
        printf 'x' >"$scratch/$name"
        chmod 0644 "$scratch/$name"
    done
    printf 'decoy' >"$work/decoy"
    chmod 0644 "$work/decoy"
}

reset
stage_file a 0600 "$SERVICE_UID:$SERVICE_UID"
check 'mode set through the descriptor' "$(stat -c %a "$scratch/a")" 600
check 'owner set through the descriptor' "$(stat -c %u:%g "$scratch/a")" "$SERVICE_UID:$SERVICE_UID"
check 'inode recorded from the descriptor' "${staged_inode[a]}" "$(stat -c %d:%i "$scratch/a")"

reset
swapped=0
chown() {
    if [[ "$swapped" -eq 0 ]]; then
        swapped=1
        mv "$scratch/a" "$work/original"
        ln -s "$work/decoy" "$scratch/a"
    fi
    command chown "$@"
}
stage_file a 0600 "$SERVICE_UID:$SERVICE_UID"
unset -f chown
check 'a swapped-in link target keeps its owner' "$(stat -c %u:%g "$work/decoy")" 0:0
check 'a swapped-in link target keeps its mode' "$(stat -c %a "$work/decoy")" 644
check 'the original file got the owner' "$(stat -c %u:%g "$work/original")" "$SERVICE_UID:$SERVICE_UID"
check 'the original file got the mode' "$(stat -c %a "$work/original")" 600

reset
stage_file a 0644 0:0
stage_file b 0644 0:0
printf 'evil' >"$scratch/b.new"
mv "$scratch/b.new" "$scratch/b"
status=0
link_set || status=$?
check 'link_set refuses a swapped scratch name' "$status" 1
check 'the first name was linked' "${linked_names[*]}" a
unlink_published
check 'the first link is removed again' "$(find "$SECRETS_DIR" -mindepth 1 | wc -l)" 0

reset
stage_file a 0644 0:0
stage_file b 0644 0:0
rm "$scratch/b"
ln -s "$work/decoy" "$scratch/b"
status=0
link_set || status=$?
check 'link_set refuses a symlink in the scratch' "$status" 1
unlink_published

reset
stage_file a 0644 0:0
stage_file b 0644 0:0
link_set
check 'link_set publishes both names' "${linked_names[*]}" 'a b'

reset
printf 'x' >"$SECRETS_DIR/a"
chmod 0600 "$SECRETS_DIR/a"
status=0
(check_present a 2>"$work/err") || status=$?
check 'check_present accepts a single link' "$status" 0
ln "$SECRETS_DIR/a" "$work/second-name"
status=0
(check_present a 2>"$work/err") || status=$?
check 'check_present refuses a second hard link' "$status" 1
check 'the refusal names the file' "$(grep -c "$SECRETS_DIR/a has more than one hard link, remove it and rerun" "$work/err")" 1

exit "$failures"
