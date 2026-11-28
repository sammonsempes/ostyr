#!/usr/bin/env bash
# Usage: crates/detection/tests/retro-live.sh <lab-state-dir>
# Live check of the retro reader on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the musl release example retro_read runs on
# the client VM against the datastore VM's ClickHouse; curl reads the real state back.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: retro-live.sh <lab-state-dir>}"
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$client_address" ]] || { echo "a client VM is required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
example="$here/target/x86_64-unknown-linux-musl/release/examples/retro_read"
[[ -x "$example" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p detection --example retro_read" >&2; exit 2; }
scp "${ssh_options[@]}" "$example" "$client_user@$client_address:/tmp/retro_read" >/dev/null
mkdir -p "$here/target/retro-live"
cargo run -q --manifest-path "$here/Cargo.toml" -p siem-schema --example print_compose_schema | awk 'BEGIN{RS=";\n"} NR==1{print; exit}' >"$here/target/retro-live/events-ddl.sql"
scp "${ssh_options[@]}" "$here/target/retro-live/events-ddl.sql" "$client_user@$client_address:/tmp/events-ddl.sql" >/dev/null
scp "${ssh_options[@]}" "$here/crates/sigma-sql/tests/rules/winsec_4625.yml" "$here/crates/sigma-sql/mappings/ecs.yaml" "$client_user@$client_address:/tmp/" >/dev/null

ssh "${ssh_options[@]}" "$client_user@$client_address" bash -s <<'REMOTE'
set -euo pipefail
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
umask 077
printf '%s' 'reader-password-lab' >reader.pw
url="https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT"
ch() {
    local reply
    reply="$(curl -sS --fail-with-body --cacert /etc/ostyr-lab/ca.pem -u "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" "$url/" --data-binary "$1")" || { echo "ch failed: ${reply:0:300}" >&2; return 1; }
    printf '%s\n' "$reply"
}
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
read_ids() {
    local tenant=$1 start=$2 end=$3 rows=$4
    /tmp/retro_read "$url" retro_reader reader.pw /etc/ostyr-lab/ca.pem ostyr "$tenant" /tmp/winsec_4625.yml /tmp/ecs.yaml "$start" "$end" "$rows"
}
stamp() { date -u -d "$1" +%Y-%m-%dT%H:%M:%SZ; }

echo "--- setup: reader user and the real events table (siem-schema DDL)"
ch "CREATE DATABASE IF NOT EXISTS ostyr" >/dev/null
ch "CREATE USER IF NOT EXISTS retro_reader IDENTIFIED BY 'reader-password-lab'" >/dev/null
ch "ALTER USER retro_reader DROP ALL SETTINGS" >/dev/null
ch "GRANT SELECT ON ostyr.events TO retro_reader" >/dev/null
ch "DROP TABLE IF EXISTS ostyr.events" >/dev/null
ch "$(sed 's/`events`/ostyr.events/' /tmp/events-ddl.sql)" >/dev/null
KNOWN_HASH=74fa251e3d1796528576b6dc40c9ab9dd1b9269bb8a5c2b4d7c1c36e2c0b717b
base="toDateTime64('2026-11-03 00:00:00', 3, 'UTC')"
ins() {
    local tenant=$1 shift_ms=$2 id_expr=$3 message=$4 code=$5 category=$6 type_expr=${7:-[]}
    ch "INSERT INTO ostyr.events (tenant, \`@timestamp\`, \`event.id\`, message, \`host.os.type\`, \`event.provider\`, \`event.code\`, \`user.name\`, \`event.category\`, \`event.type\`)
        SELECT '$tenant', $base + toIntervalMillisecond($shift_ms), $id_expr, '$message', 'windows', 'Microsoft-Windows-Security-Auditing', '$code', 'root-admin', $category, $type_expr" >/dev/null
}
ins tenant-a 123 "'e-1'" "logon failed" 4625 "['authentication']" "['denied']"
ins tenant-a 1000 "''" "empty id" 4625 "[]"
ins tenant-a 2000 "'victim-id'" "first" 4625 "[]"
ins tenant-a 3000 "'victim-id'" "forged duplicate" 4625 "[]"
ins tenant-a 4000 "concat(repeat('x', 524288), repeat('x', 524288))" "huge id" 4625 "[]"
ins tenant-a 5000 "concat('a', char(7), 'b')" "bell id" 4625 "[]"
ins tenant-a 6000 "concat('a', unhex('E280AE'), 'b')" "rtl id" 4625 "[]"
ins tenant-a 7000 "unhex('FF')" "invalid utf8 id" 4625 "[]"
ins tenant-a 8000 "'other-code'" "not a logon failure" 4624 "[]"
ins tenant-b 1000 "'b-match'" "other tenant" 4625 "[]"
ins tenant-c 1000 "''" "empty one" 4625 "[]"
ins tenant-c 1000 "''" "empty two" 4625 "[]"
ins tenant-c 2000 "''" "empty two" 4625 "[]"
start=2026-11-02T00:00:00Z
end=2026-11-05T00:00:00Z
now_text="$(stamp now)"

echo "--- tenant a, room for all: five identities in time order, three ids refused alone, no other tenant, no other code"
out="$(read_ids tenant-a "$start" "$end" 100)"
echo "$out" | cut -c1-400
check "known row identity pinned" "e-1:$KNOWN_HASH" "$(echo "$out" | grep -o "e-1:[0-9a-f]\{64\}")"
check "complete with three refused" 'complete' "$(echo "$out" | cut -d' ' -f1)"
check "refused count" 'refused=3' "$(echo "$out" | grep -o 'refused=[0-9]*')"
check "empty id is the hash alone" 1 "$(echo "$out" | grep -o '"[0-9a-f]\{64\}"' | wc -l)"
check "forged duplicate has two distinct identities" 2 "$(echo "$out" | grep -o 'victim-id:[0-9a-f]\{64\}' | sort -u | wc -l)"
check "1 MB id is cut to 63 characters plus the hash" 1 "$(echo "$out" | grep -c "\"$(printf 'x%.0s' $(seq 63)):[0-9a-f]\{64\}\"")"
check "no other tenant" 0 "$(echo "$out" | grep -c 'b-match')"
check "reply stays small" 1 "$([[ ${#out} -lt 1000 ]] && echo 1 || echo 0)"

echo "--- all event.id empty: different content gives different identities"
out="$(read_ids tenant-c "$start" "$end" 10)"
check "three rows, all empty ids" 3 "$(echo "$out" | grep -o '"[0-9a-f]\{64\}"' | wc -l)"
check "identical content at another time is another identity" 3 "$(echo "$out" | grep -o '"[0-9a-f]\{64\}"' | sort -u | wc -l)"

echo "--- tenant b sees only its own"
check "tenant b" 1 "$(read_ids tenant-b "$start" "$end" 10 | grep -c 'b-match:')"

echo "--- row cap 5 of 8 rows: named, the first five in time order"
out="$(read_ids tenant-a "$start" "$end" 5)"
check "row cap" 'row_cap cap=5' "$(echo "$out" | cut -d' ' -f1,2)"
check "row cap refused" 'refused=0' "$(echo "$out" | grep -o 'refused=[0-9]*')"

echo "--- exactly the cap is complete"
check "exact cap" 'complete' "$(read_ids tenant-a "$start" "$end" 8 | cut -d' ' -f1)"

echo "--- a window over seven days is refused before any request"
out="$(read_ids tenant-a "$(stamp '9 days ago')" "$now_text" 10)"
check "window too long" 'error the window is longer than 7 days' "$out"

echo "--- a changed ClickHouse setting outside the pins is refused"
ch "ALTER USER retro_reader SETTINGS skip_unavailable_shards = 1" >/dev/null
out="$(read_ids tenant-a "$start" "$end" 100)"
echo "$out"
check "changed setting" 'error reader_profile_changed: 1 setting(s) outside the allowed list' "$out"
ch "ALTER USER retro_reader DROP ALL SETTINGS" >/dev/null
check "clean again" 'complete' "$(read_ids tenant-a "$start" "$end" 100 | cut -d' ' -f1)"

echo "--- a profile that cuts the reply silently (limit = 2) cannot hide rows: the pin wins"
ch "ALTER USER retro_reader SETTINGS limit = 2" >/dev/null
out="$(read_ids tenant-a "$start" "$end" 100)"
check "profile limit pinned away" 'complete refused=3' "$(echo "$out" | cut -d' ' -f1) $(echo "$out" | grep -o 'refused=[0-9]*')"
ch "ALTER USER retro_reader DROP ALL SETTINGS" >/dev/null

echo "--- a write is refused for the reader"
if curl -sS --fail-with-body --cacert /etc/ostyr-lab/ca.pem -u retro_reader:reader-password-lab "$url/?readonly=2" --data-binary "INSERT INTO ostyr.events (tenant) VALUES ('x')" >/dev/null 2>&1; then echo "FAIL reader could write" ; failures=$((failures + 1)); else echo "PASS write refused by grants"; fi
ch "DROP USER IF EXISTS retro_reader" >/dev/null
ch "DROP TABLE IF EXISTS ostyr.events" >/dev/null
echo "failures=$failures"
exit "$failures"
REMOTE
