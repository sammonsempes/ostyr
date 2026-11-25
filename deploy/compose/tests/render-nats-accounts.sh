#!/usr/bin/env bash
set -euo pipefail
readonly INIT_FILE="${1:?init.sh path}"
readonly SCRATCH_PARENT="$(dirname "$0")/../../../target"
mkdir -p "$SCRATCH_PARENT"
work="$(mktemp -d "$SCRATCH_PARENT/nats-accounts.XXXXXX")"
trap 'rm -rf "$work"' EXIT
{
    grep -E '^readonly NATS_' "$INIT_FILE"
    for name in nats_consumer_exports nats_consumer_account; do
        sed -n "/^${name}() {/,/^}/p" "$INIT_FILE"
    done
    sed -n '/^nats_accounts() {/,/^ACCOUNTS$/p' "$INIT_FILE"
    printf '}\n'
} >"$work/functions.sh"
(
    # shellcheck source=/dev/null
    source "$work/functions.sh"
    nats_accounts adminpw gatewaypw siempw metricspw
)
