#!/usr/bin/env bash
# Usage: lab/tests/egress-profile-test.sh
# Checks egress field parsing, the refusal of proxy for attack profiles and the allowlist-to-regex conversion. No VM boots.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

work="$(mktemp -d "$REPO_DIR/target/egress-profile.XXXXXX")"
trap 'rm -rf "$work"' EXIT
failures=0

expect() {
    local description="$1"
    shift
    if "$@"; then
        log "ok   $description"
    else
        log "FAIL $description"
        failures=$((failures + 1))
    fi
}

refused() (
    profile_egress "$1" >/dev/null
)

fails() {
    ! "$@"
}

printf 'vms:\n  - name: a\n    base_image: ubuntu-2404.qcow2\n' >"$work/none.yaml"
printf 'egress: proxy\nvms:\n  - name: a\n    base_image: ubuntu-2404.qcow2\n' >"$work/proxy.yaml"
printf 'egress: proxy\nvms:\n  - name: a\n    base_image: attacker.qcow2\n' >"$work/attack.yaml"
printf 'egress: none\nvms:\n  - name: a\n    base_image: attacker.qcow2\n' >"$work/attack-none.yaml"
printf 'egress: open\nvms:\n  - name: a\n    base_image: ubuntu-2404.qcow2\n' >"$work/bad.yaml"
printf 'a.example.com\n.example.org\n' >"$work/allow.txt"

expect "default egress is none" test "$(profile_egress "$work/none.yaml")" = none
expect "egress proxy is read" test "$(profile_egress "$work/proxy.yaml")" = proxy
expect "proxy refused for an attack profile" fails refused "$work/attack.yaml"
expect "none accepted for an attack profile" test "$(profile_egress "$work/attack-none.yaml")" = none
expect "unknown egress refused" fails refused "$work/bad.yaml"
expect "exact host regex" grep -qxF '^a\.example\.com$' <(proxy_filter_regexes "$work/allow.txt")
expect "suffix regex" grep -qxF '(^|\.)example\.org$' <(proxy_filter_regexes "$work/allow.txt")

((failures == 0)) || die "$failures check(s) failed"
log "all egress profile checks passed"
