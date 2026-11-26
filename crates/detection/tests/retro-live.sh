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
ch() { curl -sS --fail-with-body --cacert /etc/ostyr-lab/ca.pem -u "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" "$url/" --data-binary "$1"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
read_ids() {
    local tenant=$1 start=$2 end=$3 rows=$4
    /tmp/retro_read "$url" retro_reader reader.pw /etc/ostyr-lab/ca.pem ostyr "$tenant" /tmp/winsec_4625.yml /tmp/ecs.yaml "$start" "$end" "$rows"
}
stamp() { date -u -d "$1" +%Y-%m-%dT%H:%M:%SZ; }

echo "--- setup: reader user and events over three days"
ch "CREATE DATABASE IF NOT EXISTS ostyr" >/dev/null
ch "CREATE USER IF NOT EXISTS retro_reader IDENTIFIED BY 'reader-password-lab'" >/dev/null
ch "ALTER USER retro_reader DROP ALL SETTINGS" >/dev/null
ch "GRANT SELECT ON ostyr.events TO retro_reader" >/dev/null
ch "DROP TABLE IF EXISTS ostyr.events" >/dev/null
ch "CREATE TABLE ostyr.events (tenant String, \`@timestamp\` DateTime('UTC'), \`event.id\` String, \`host.os.type\` String, \`event.provider\` String, \`event.code\` String, \`user.name\` String) ENGINE = MergeTree ORDER BY (tenant, \`@timestamp\`)" >/dev/null
row() { printf "('%s', now() - %s, '%s', 'windows', 'Microsoft-Windows-Security-Auditing', '%s', '%s')" "$1" "$2" "$3" "$4" "$5"; }
ch "INSERT INTO ostyr.events VALUES
 $(row tenant-a 172800 d2-match 4625 root-admin),
 $(row tenant-a 90000 d1-match 4625 sys-admin),
 $(row tenant-a 3600 h1-match 4625 web-admin),
 $(row tenant-a 3000 h1-other 4624 web-admin),
 $(row tenant-a 600 m10-match 4625 db-admin),
 $(row tenant-a 300 m5-user 4625 bob),
 $(row tenant-b 3600 b-match 4625 web-admin),
 $(row tenant-a 1296000 old-match 4625 old-admin)" >/dev/null
now_text="$(stamp now)"
three_days="$(stamp '3 days ago')"
one_day="$(stamp '1 day ago')"

echo "--- three days, room for all: the four matches, in time order, no other tenant, no old one"
out="$(read_ids tenant-a "$three_days" "$now_text" 10)"
echo "$out"
check "complete" 'complete ids=["d2-match", "d1-match", "h1-match", "m10-match"] refused=0' "$out"

echo "--- tenant b sees only its own"
check "tenant b" 'complete ids=["b-match"] refused=0' "$(read_ids tenant-b "$three_days" "$now_text" 10)"

echo "--- a one-day window"
check "one day" 'complete ids=["h1-match", "m10-match"] refused=0' "$(read_ids tenant-a "$one_day" "$now_text" 10)"

echo "--- row cap 3 of 4 matches: named, the first three in time order"
out="$(read_ids tenant-a "$three_days" "$now_text" 3)"
echo "$out"
check "row cap" 'row_cap cap=3 ids=["d2-match", "d1-match", "h1-match"] refused=0' "$out"

echo "--- exactly the cap is complete"
check "exact cap" 'complete ids=["d2-match", "d1-match", "h1-match", "m10-match"] refused=0' "$(read_ids tenant-a "$three_days" "$now_text" 4)"

echo "--- a window over seven days is refused before any request"
out="$(read_ids tenant-a "$(stamp '9 days ago')" "$now_text" 10)"
check "window too long" 'error the window is longer than 7 days' "$out"

echo "--- a changed ClickHouse setting outside the pins is refused"
ch "ALTER USER retro_reader SETTINGS skip_unavailable_shards = 1" >/dev/null
out="$(read_ids tenant-a "$three_days" "$now_text" 10)"
echo "$out"
check "changed setting" 'error reader_profile_changed: 1 setting(s) outside the allowed list' "$out"
ch "ALTER USER retro_reader DROP ALL SETTINGS" >/dev/null
check "clean again" 'complete ids=["d2-match", "d1-match", "h1-match", "m10-match"] refused=0' "$(read_ids tenant-a "$three_days" "$now_text" 10)"

echo "--- a profile that cuts the reply silently (limit = 2) cannot hide rows: the pin wins"
ch "ALTER USER retro_reader SETTINGS limit = 2" >/dev/null
out="$(read_ids tenant-a "$three_days" "$now_text" 10)"
echo "$out"
check "profile limit pinned away" 'complete ids=["d2-match", "d1-match", "h1-match", "m10-match"] refused=0' "$out"
ch "ALTER USER retro_reader DROP ALL SETTINGS" >/dev/null

echo "--- a write is refused for the reader"
if curl -sS --fail-with-body --cacert /etc/ostyr-lab/ca.pem -u retro_reader:reader-password-lab "$url/?readonly=2" --data-binary "INSERT INTO ostyr.events (tenant) VALUES ('x')" >/dev/null 2>&1; then echo "FAIL reader could write" ; failures=$((failures + 1)); else echo "PASS write refused by grants"; fi
ch "DROP USER IF EXISTS retro_reader" >/dev/null
ch "DROP TABLE IF EXISTS ostyr.events" >/dev/null
echo "failures=$failures"
exit "$failures"
REMOTE
