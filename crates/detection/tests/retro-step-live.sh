#!/usr/bin/env bash
# Usage: crates/detection/tests/retro-step-live.sh <lab-state-dir>
# Live check of one retro step on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the musl release example retro_step runs on the client VM
# against the datastore VM's ClickHouse (reader) and PostgreSQL (alerts); psql reads the real state back.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: retro-step-live.sh <lab-state-dir>}"
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$client_address" ]] || { echo "a client VM is required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
example="$here/target/x86_64-unknown-linux-musl/release/examples/retro_step"
[[ -x "$example" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p detection --example retro_step" >&2; exit 2; }
scp "${ssh_options[@]}" "$example" "$client_user@$client_address:/tmp/retro_step" >/dev/null
mkdir -p "$here/target/retro-live"
cargo run -q --manifest-path "$here/Cargo.toml" -p siem-schema --example print_compose_schema | awk 'BEGIN{RS=";\n"} NR==1{print; exit}' >"$here/target/retro-live/events-ddl.sql"
scp "${ssh_options[@]}" "$here/target/retro-live/events-ddl.sql" "$client_user@$client_address:/tmp/events-ddl.sql" >/dev/null
sed 's/^level: medium$/level: medium\ntags:\n  - ostyr.retro/' "$here/crates/sigma-sql/tests/rules/winsec_4625.yml" >"$here/target/retro-live/rule.yml"
scp "${ssh_options[@]}" "$here/target/retro-live/rule.yml" "$here/crates/sigma-sql/mappings/ecs.yaml" "$client_user@$client_address:/tmp/" >/dev/null

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
printf '%s' "$POSTGRES_PASSWORD" >pg.pw
cat >pg.json <<EOF
{"host":"$DATASTORE_DOMAIN","port":$POSTGRES_PORT,"database":"$POSTGRES_DATABASE","user":"$POSTGRES_USER","password_file":"$work/pg.pw","ca_file":"/etc/ostyr-lab/ca.pem"}
EOF
url="https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT"
ch() {
    local reply
    reply="$(curl -sS --fail-with-body --cacert /etc/ostyr-lab/ca.pem -u "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" "$url/" --data-binary "$1")" || { echo "ch failed: ${reply:0:300}" >&2; return 1; }
    printf '%s\n' "$reply"
}
pg() {
    PGPASSWORD="$POSTGRES_PASSWORD" psql "host=$DATASTORE_DOMAIN port=$POSTGRES_PORT user=$POSTGRES_USER dbname=$POSTGRES_DATABASE sslmode=verify-full sslrootcert=/etc/ostyr-lab/ca.pem" --tuples-only --no-align --quiet -c "$1"
}
step() {
    /tmp/retro_step "$url" retro_reader reader.pw /etc/ostyr-lab/ca.pem ostyr pg.json "$1" /tmp/rule.yml /tmp/ecs.yaml "$3" "$2" 100
}
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
rule_id='retro:00000000-0000-4000-8000-000000000294'
loss_id='retro.loss:00000000-0000-4000-8000-000000000294'

echo "--- setup: reader user and the real events table"
ch "CREATE DATABASE IF NOT EXISTS ostyr" >/dev/null
ch "CREATE USER IF NOT EXISTS retro_reader IDENTIFIED BY 'reader-password-lab'" >/dev/null
ch "ALTER USER retro_reader DROP ALL SETTINGS" >/dev/null
ch "GRANT SELECT ON ostyr.events TO retro_reader" >/dev/null
ch "DROP TABLE IF EXISTS ostyr.events" >/dev/null
ch "$(sed 's/`events`/ostyr.events/' /tmp/events-ddl.sql)" >/dev/null
base="toDateTime64('2026-11-03 00:00:00', 3, 'UTC')"
ins() {
    local tenant=$1 shift_ms=$2 id_expr=$3 message=$4
    ch "INSERT INTO ostyr.events (tenant, \`@timestamp\`, \`event.id\`, message, \`host.os.type\`, \`event.provider\`, \`event.code\`, \`user.name\`, \`event.category\`, \`event.type\`)
        SELECT '$tenant', $base + toIntervalMillisecond($shift_ms), $id_expr, '$message', 'windows', 'Microsoft-Windows-Security-Auditing', '4625', 'root-admin', [], []" >/dev/null
}
ins tenant-a 123 "'e-1'" "logon failed"
ins tenant-a 1000 "''" "empty id"
ins tenant-a 2000 "'victim-id'" "first"
ins tenant-a 3000 "'victim-id'" "forged duplicate"
ins tenant-a 4000 "concat(repeat('x', 524288), repeat('x', 524288))" "huge id"
ins tenant-a 5000 "concat('a', char(7), 'b')" "bell id"
ins tenant-a 6000 "concat('a', unhex('E280AE'), 'b')" "rtl id"
ins tenant-a 7000 "concat('a', unhex('E280A8'), 'b')" "line separator id"
ins tenant-a 8000 "unhex('FF')" "invalid utf8 id"
ins tenant-b 1000 "'b-match'" "other tenant"
pg "DO \$\$ BEGIN IF to_regclass('alert_outbox') IS NOT NULL THEN DELETE FROM alert_outbox WHERE tenant IN ('tenant-a', 'tenant-b'); END IF; END \$\$" >/dev/null
pg "DO \$\$ BEGIN IF to_regclass('alerts') IS NOT NULL THEN DELETE FROM alerts WHERE tenant IN ('tenant-a', 'tenant-b'); END IF; END \$\$" >/dev/null
now=2026-11-10T00:00:00Z
rm -f cursors.json

echo "--- first step of tenant a: five alerts stored, four ids refused alone, cursor saved"
out="$(step tenant-a "$now" cursors.json 2>&1 || true)"
echo "$out"
check "outcome" 'Complete' "$(echo "$out" | grep -o 'outcome: [A-Za-z]*' | cut -d' ' -f2)"
check "found" 'found: 5' "$(echo "$out" | grep -o 'found: [0-9]*')"
check "refused" 'refused_ids: 4' "$(echo "$out" | grep -o 'refused_ids: [0-9]*')"
check "stored" 'stored: 5' "$(echo "$out" | grep -o 'stored: [0-9]*')"
check "alerts in PostgreSQL" 5 "$(pg "SELECT count(*) FROM alerts WHERE tenant = 'tenant-a' AND rule_id = '$rule_id'")"
check "other tenant has none" 0 "$(pg "SELECT count(*) FROM alerts WHERE tenant = 'tenant-b' AND rule_id = '$rule_id'")"
check "cursor moved one step" 1 "$(grep -c '"next":1793667600' cursors.json)"

echo "--- rerun with the cursor lost: the same window is read again and adds nothing"
rm -f cursors.json
out="$(step tenant-a "$now" cursors.json 2>&1 || true)"
echo "$out"
check "rerun stores nothing" 'stored: 0' "$(echo "$out" | grep -o 'stored: [0-9]*')"
check "still five alerts" 5 "$(pg "SELECT count(*) FROM alerts WHERE tenant = 'tenant-a' AND rule_id = '$rule_id'")"

echo "--- the next step starts at the saved cursor and finds nothing new"
out="$(step tenant-a "$now" cursors.json 2>&1 || true)"
echo "$out"
check "next window empty" 'found: 0' "$(echo "$out" | grep -o 'found: [0-9]*')"
check "still five alerts" 5 "$(pg "SELECT count(*) FROM alerts WHERE tenant = 'tenant-a' AND rule_id = '$rule_id'")"

echo "--- a row cap at 3 rows in the first window reads the capped second again"
rm -f cursors.json
out="$(/tmp/retro_step "$url" retro_reader reader.pw /etc/ostyr-lab/ca.pem ostyr pg.json tenant-a /tmp/rule.yml /tmp/ecs.yaml cursors.json "$now" 3 2>&1 || true)"
echo "$out"
check "row cap outcome" 'RowCap' "$(echo "$out" | grep -o 'outcome: [A-Za-z]*' | cut -d' ' -f2)"
check "no loss in distinct seconds" 'losses: 0' "$(echo "$out" | grep -o 'losses: [0-9]*')"
check "cursor at the second of the last row" 1 "$(grep -c '"next":1793664002' cursors.json)"

echo "--- a cursor ahead of now (4000000000) restarts from the horizon, warns, adds nothing"
rm -f cursors.json
step tenant-a "$now" cursors.json >/dev/null 2>&1 || true
sed -i 's/"next":[0-9]*/"next":4000000000/' cursors.json
out="$(step tenant-a "$now" cursors.json 2>&1 || true)"
echo "$out"
check "ahead warning" 1 "$(echo "$out" | grep -c 'cursor_ahead=1')"
check "ahead restarts and reads" 'found: 5' "$(echo "$out" | grep -o 'found: [0-9]*')"
check "ahead stores nothing twice" 'stored: 0' "$(echo "$out" | grep -o 'stored: [0-9]*')"
check "ahead cursor repaired" 1 "$(grep -c '"next":1793667600' cursors.json)"

echo "--- a cursor at 0 is clamped to the horizon with a named loss alert"
sed -i 's/"next":[0-9]*/"next":0/' cursors.json
out="$(step tenant-a "$now" cursors.json 2>&1 || true)"
echo "$out"
check "stale warning" 1 "$(echo "$out" | grep -c 'retro cursor older than the horizon')"
check "stale loss counted" 'losses: 1' "$(echo "$out" | grep -o 'losses: [0-9]*')"
check "stale stored only the loss" 'stored: 1' "$(echo "$out" | grep -o 'stored: [0-9]*')"
check "loss alert in PostgreSQL" 1 "$(pg "SELECT count(*) FROM alerts WHERE tenant = 'tenant-a' AND rule_id = '$loss_id'")"
check "still five retro alerts" 5 "$(pg "SELECT count(*) FROM alerts WHERE tenant = 'tenant-a' AND rule_id = '$rule_id'")"

echo "--- a changed profile setting stops the step with the old cursor"
rm -f cursors.json
ch "ALTER USER retro_reader SETTINGS skip_unavailable_shards = 1" >/dev/null
out="$(step tenant-a "$now" cursors.json 2>&1 || true)"
echo "$out"
check "refused" 1 "$(echo "$out" | grep -c 'ReaderProfileChanged')"
check "no cursor written" 0 "$(test -e cursors.json && echo 1 || echo 0)"
ch "ALTER USER retro_reader DROP ALL SETTINGS" >/dev/null

ch "DROP USER IF EXISTS retro_reader" >/dev/null
ch "DROP TABLE IF EXISTS ostyr.events" >/dev/null
echo "failures=$failures"
exit "$failures"
REMOTE
