#!/usr/bin/env bash
# Usage: sudo lock-proof.sh <path to init.sh>
# Holds one init.sh at its first ln, runs a second one (refused by the lock), releases the first and checks it finished a full, matching TLS set.
set -euo pipefail

readonly HOLD_STEPS=600
readonly HOLD_PAUSE=0.1
init_source="$(readlink -f "${1:?usage: lock-proof.sh <init.sh>}")"
work="$(mktemp -d)"
readonly init_source work
trap 'rm -rf "$work"' EXIT
chmod 0755 "$work"
mkdir "$work/bin" "$work/run"
chmod 0755 "$work/run"
cp "$init_source" "$work/run/init.sh"
real_ln="$(command -v ln)"
readonly real_ln
cat >"$work/bin/ln" <<WRAPPER
#!/usr/bin/env bash
if [[ ! -e $work/marker ]]; then
    : >$work/marker
    for step in \$(seq 1 $HOLD_STEPS); do
        [[ -e $work/release ]] && break
        sleep $HOLD_PAUSE
    done
fi
exec $real_ln "\$@"
WRAPPER
chmod +x "$work/bin/ln"
PATH="$work/bin:$PATH" "$work/run/init.sh" lock.example >"$work/first.out" 2>&1 &
first_pid=$!
for step in $(seq 1 "$HOLD_STEPS"); do
    [[ -e "$work/marker" ]] && break
    sleep "$HOLD_PAUSE"
done
second_status=0
"$work/run/init.sh" lock.example >"$work/second.out" 2>&1 || second_status=$?
: >"$work/release"
first_status=0
wait "$first_pid" || first_status=$?
printf 'second rc=%s: %s\n' "$second_status" "$(tail -1 "$work/second.out")"
printf 'first rc=%s: %s\n' "$first_status" "$(tail -1 "$work/first.out")"
[[ "$second_status" -ne 0 ]] && grep -q 'holds the lock' "$work/second.out"
[[ "$first_status" -eq 0 ]]
openssl verify -CAfile "$work/run/secrets/ca.crt" "$work/run/secrets/pg_server.crt" "$work/run/secrets/api_tls.crt"
printf 'lock proof passed\n'
