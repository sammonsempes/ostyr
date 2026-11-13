#!/usr/bin/env bash
# Usage: lab/tests/proxmox-single-test.sh
# No VM: checks the setup script's argument handling and that the key digest check fails on a wrong key.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly SETUP="$LAB_DIR/profiles/proxmox-single.setup.sh"
readonly KEY="$LAB_DIR/images/keys/proxmox-release-bookworm.gpg"
readonly DIGEST="$LAB_DIR/images/keys/proxmox-release-bookworm.gpg.sha512"

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
fails() { ! "$@" >/dev/null 2>&1; }

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
printf 'not the proxmox key\n' >"$work_dir/proxmox-release-bookworm.gpg"

check "no argument is refused" fails "$SETUP"
check "missing lab prefix is refused" fails "$SETUP" "$work_dir"
check "missing digest argument is refused" fails "$SETUP" --check-key "$KEY"
check "the pinned key passes" "$SETUP" --check-key "$KEY" "$DIGEST"
check "a wrong key fails" fails "$SETUP" --check-key "$work_dir/proxmox-release-bookworm.gpg" "$DIGEST"
check "the real run refuses a state dir without vms.txt" fails "$SETUP" "$work_dir" ostyr-x
exit "$failures"
