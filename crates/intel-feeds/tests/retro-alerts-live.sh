#!/usr/bin/env bash
# Usage: crates/intel-feeds/tests/retro-alerts-live.sh <lab-state-dir>
# Live check of the retro alerts and schedule on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the musl release examples
# intel_load, retro_run and retro_schedule run on the client VM against the datastore VM (ClickHouse events and IOCs, PostgreSQL alerts); psql and
# curl read the real state back.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: retro-alerts-live.sh <lab-state-dir>}"
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$client_address" ]] || { echo "a client VM is required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
release="$here/target/x86_64-unknown-linux-musl/release/examples"
for example in intel_load retro_run retro_schedule; do
    [[ -x "$release/$example" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p intel-feeds --examples" >&2; exit 2; }
    scp "${ssh_options[@]}" "$release/$example" "$client_user@$client_address:/tmp/$example" >/dev/null
done

ssh "${ssh_options[@]}" "$client_user@$client_address" bash -s <<'REMOTE'
set -euo pipefail
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
umask 077
printf '%s' "$CLICKHOUSE_PASSWORD" >ch.pw
printf '%s' "$POSTGRES_PASSWORD" >pg.pw
printf '%s' 'reader-password-lab' >reader.pw
cat >pg.yaml <<YAML
host: $DATASTORE_DOMAIN
port: $POSTGRES_PORT
database: $POSTGRES_DATABASE
user: $POSTGRES_USER
password_file: $work/pg.pw
ca_file: /etc/ostyr-lab/ca.pem
YAML
url="https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT"
ch() { curl -sS --fail-with-body --cacert /etc/ostyr-lab/ca.pem -u "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" "$url/" --data-binary "$1"; }
export PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full PGSSLROOTCERT=/etc/ostyr-lab/ca.pem
sql() { psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -c "$1"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}

clickhouse_block() {
    cat <<YAML
  url: $url
  user: $1
  password_file: $work/$2
  ca_file: /etc/ostyr-lab/ca.pem
  database: ostyr
  table: iocs
  dictionary: ioc_trie
  dictionary_user: ostyr_dict
  dictionary_port: 9440
  tenant: $3
YAML
}
feeds_file() {
    local name=$1 matches=$2 interval=$3 window=$4
    {
        printf 'feeds:\n  - name: lab\n    format: crowdsec\n    path: unused.txt\n    tlp: amber\nclickhouse:\n'
        clickhouse_block "$CLICKHOUSE_USER" ch.pw tenant-a
        printf 'retro:\n  reader:\n'
        clickhouse_block retro_reader reader.pw tenant-a | sed 's/^/  /'
        printf '  events_database: ostyr\n  events_table: events\n  max_matches: %s\n  interval_seconds: %s\n  window_seconds: %s\n  pg_settings: %s/pg.yaml\n' \
            "$matches" "$interval" "$window" "$work"
    } >"$name"
}
reader_file() {
    printf 'feeds: []\nclickhouse:\n' >"$1"
    clickhouse_block retro_reader reader.pw tenant-a >>"$1"
}

echo "--- setup: reader user, events, IOCs"
ch "CREATE DATABASE IF NOT EXISTS ostyr" >/dev/null
ch "CREATE USER IF NOT EXISTS retro_reader IDENTIFIED BY 'reader-password-lab'" >/dev/null
ch "GRANT SELECT ON ostyr.events TO retro_reader" >/dev/null
ch "GRANT SELECT ON ostyr.iocs TO retro_reader" >/dev/null
ch "GRANT dictGet ON ostyr.ioc_trie TO retro_reader" >/dev/null
ch "DROP TABLE IF EXISTS ostyr.events_slow" >/dev/null
ch "DROP TABLE IF EXISTS ostyr.events" >/dev/null
ch "CREATE TABLE ostyr.events (tenant String, \`@timestamp\` DateTime('UTC'), \`source.ip\` String, \`destination.ip\` String, \`host.name\` String) ENGINE = MergeTree ORDER BY (tenant, \`@timestamp\`)" >/dev/null
ch "CREATE VIEW ostyr.events_slow AS SELECT * FROM ostyr.events WHERE sleepEachRow(0.5) = 0" >/dev/null
ch "GRANT SELECT ON ostyr.events_slow TO retro_reader" >/dev/null
ch "ALTER TABLE ostyr.iocs DELETE WHERE 1 SETTINGS mutations_sync = 2" >/dev/null 2>&1 || true
now_sql="now() - 60"
ch "INSERT INTO ostyr.events VALUES
 ('tenant-a', $now_sql, '192.0.2.1', '10.0.0.1', 'web-1'),
 ('tenant-a', $now_sql, '192.0.2.1', '10.0.0.1', 'web-1'),
 ('tenant-a', $now_sql, '10.0.0.2', '192.0.2.2', 'web-2'),
 ('tenant-a', $now_sql, '198.51.100.7', '10.0.0.3', 'db-1'),
 ('tenant-a', $now_sql, '198.51.100.8', '10.0.0.3', 'db-1'),
 ('tenant-a', $now_sql, '192.0.2.3', '10.0.0.3', concat('nul', char(0), 'host')),
 ('tenant-a', $now_sql, '192.0.2.4', '10.0.0.3', repeat('h', 10240)),
 ('tenant-a', $now_sql, '198.51.100.9', '10.0.0.3', concat('blank', unhex('E385A4'), unhex('E1859F'), 'host')),
 ('tenant-a', $now_sql, 'not-an-ip', '', 'noise-1'),
 ('tenant-a', $now_sql, '', '::', 'noise-2'),
 ('tenant-b', $now_sql, '192.0.2.1', '10.0.0.1', 'tenant-b-host')" >/dev/null
for address in 192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4; do
    printf '{"ioc_type":"ipv4","value":"%s","sources":[{"feed":"lab","version":"v1"}],"first_seen":"2026-11-03T12:00:00Z","last_seen":"2026-11-03T12:00:00Z","confidence":50,"tlp":"red","expires_at":"2099-01-01T00:00:00Z","tags":{"malware":[],"actor":[],"campaign":[]}}\n' "$address"
done >iocs.jsonl
printf '{"ioc_type":"cidr","value":"198.51.100.0/24","sources":[{"feed":"lab","version":"v1"}],"first_seen":"2026-11-03T12:00:00Z","last_seen":"2026-11-03T12:00:00Z","confidence":50,"tlp":"amber","expires_at":"2099-01-01T00:00:00Z","tags":{"malware":[],"actor":[],"campaign":[]}}\n' >>iocs.jsonl
feeds_file small.yaml 3 60 360
feeds_file full.yaml 499 60 360
reader_file reader.yaml
sql "DELETE FROM alert_outbox WHERE tenant = 'tenant-a'" >/dev/null 2>&1 || true
sql "DELETE FROM alerts WHERE tenant = 'tenant-a'" >/dev/null 2>&1 || true
/tmp/intel_load full.yaml iocs.jsonl
sleep 3
echo "dictionary status: $(ch "SELECT status FROM system.dictionaries WHERE name = 'ioc_trie'")"

echo "--- max_matches 3 with 7 groups: 3 alerts and the truncation alert"
/tmp/retro_schedule small.yaml audit-small.jsonl small.state 1 | tee small.out
check "truncated run" "4" "$(sql "SELECT count(*) FROM alerts WHERE tenant = 'tenant-a' AND rule_id LIKE 'intel.retro_match.%'")"
check "truncation alert" "1" "$(sql "SELECT count(*) FROM alerts WHERE tenant = 'tenant-a' AND rule_id = 'intel.retro_match.truncated'")"
grep -q 'truncated=true' small.out && echo "PASS summary names truncated" || { echo "FAIL summary names truncated"; failures=$((failures + 1)); }

echo "--- full run twice on the same window (two rounds one interval apart): inserted N of M, then 0"
/tmp/retro_schedule full.yaml audit-full.jsonl full.state 15 | tee full.out
check "alerts for tenant-a" "7" "$(sql "SELECT count(*) FROM alerts WHERE tenant = 'tenant-a' AND rule_id = 'intel.retro_match.ip'")"
check "no alert for tenant-b" "0" "$(sql "SELECT count(*) FROM alerts WHERE tenant = 'tenant-b'")"
check "fixed titles only" "1" "$(sql "SELECT count(DISTINCT rule_title) FROM alerts WHERE rule_id = 'intel.retro_match.ip'")"
check "no indicator in a title or a host of another tenant" "0" "$(sql "SELECT count(*) FROM alerts WHERE rule_title LIKE '%192.0.2%' OR host_name = 'tenant-b-host'")"
check "NUL host escaped" "nul\\u{0}host" "$(sql "SELECT host_name FROM alerts WHERE host_name LIKE 'nul%'")"
check "U+3164 and U+115F host escaped" 'blank\u{3164}\u{115f}host' "$(sql "SELECT host_name FROM alerts WHERE host_name LIKE 'blank%'")"
check "10 KB host cut to 256" "256" "$(sql "SELECT max(length(host_name)) FROM alerts WHERE rule_id = 'intel.retro_match.ip'")"
sql "SELECT rule_id, severity, left(event_ids::text, 20), left(summary, 200) FROM alerts WHERE tenant = 'tenant-a' ORDER BY id LIMIT 3"
echo "non-IP count in the summary: $(grep -o 'not_an_ip=[0-9]*' full.out | sort -u | tr '\n' ' ')"
grep -q 'inserted=0' full.out && echo "PASS second round inserted 0" || { echo "FAIL second round inserted 0"; failures=$((failures + 1)); }

echo "--- live reload: a window shorter than interval plus margin is refused, the old settings stay"
cp full.yaml reload.yaml
/tmp/retro_schedule reload.yaml audit-reload.jsonl reload.state 6 >reload.out &
reload_pid=$!
sleep 2
sed -i 's/window_seconds: 360/window_seconds: 100/' reload.yaml
sleep 3
sed -i 's/interval_seconds: 60/interval_seconds: 61/; s/window_seconds: 100/window_seconds: 400/' reload.yaml
wait "$reload_pid"
cat reload.out
echo "audit entries: $(wc -l <audit-reload.jsonl)"
grep -i 'refus' audit-reload.jsonl | cut -c1-400 || echo 'FAIL no refusal audited'

echo "--- restart: the saved window end names a gap, a missing or bad state file is named"
now_epoch="$(date +%s)"
printf 'tenant-a %s' "$((now_epoch - 7200))" >gap.state
/tmp/retro_schedule full.yaml audit-gap.jsonl gap.state 1 | tee gap.out
grep -q '^start resumed$' gap.out && grep -q 'gap=true' gap.out && echo "PASS restart after downtime longer than the window names gap" || { echo "FAIL gap not named"; failures=$((failures + 1)); }
check "state file holds the new end" "1" "$(awk -v floor="$now_epoch" '$2 >= floor { print 1 }' gap.state)"
/tmp/retro_schedule full.yaml audit-gap2.jsonl gap.state 1 | tee gap2.out
grep -q 'gap=false' gap2.out && echo "PASS an immediate restart names no gap" || { echo "FAIL gap named on a covered restart"; failures=$((failures + 1)); }
/tmp/retro_schedule full.yaml audit-none.jsonl none.state 1 | tee none.out
grep -q '^start no_previous_run$' none.out && echo "PASS missing state named once" || { echo "FAIL no_previous_run not named"; failures=$((failures + 1)); }
printf 'tenant-a %s' "$(printf '9%.0s' $(seq 1 21))" >bad.state
/tmp/retro_schedule full.yaml audit-bad.jsonl bad.state 1 | tee bad.out
grep -q '^start state_unreadable$' bad.out && echo "PASS oversized state named" || { echo "FAIL state_unreadable not named"; failures=$((failures + 1)); }
printf 'tenant-a 253402300799' >ahead.state
/tmp/retro_schedule full.yaml audit-ahead.jsonl ahead.state 1 | tee ahead.out
grep -q '^start state_ahead$' ahead.out && echo "PASS forged future end named" || { echo "FAIL state_ahead not named"; failures=$((failures + 1)); }
printf 'tenant-b %s' "$((now_epoch - 60))" >other.state
/tmp/retro_schedule full.yaml audit-other.jsonl other.state 1 | tee other.out
grep -q '^start state_other_tenant$' other.out && echo "PASS other tenant state named" || { echo "FAIL state_other_tenant not named"; failures=$((failures + 1)); }
printf 'victim-bytes' >victim.txt
ln -s victim.txt plant.state.tmp
printf 'tenant-a %s' "$((now_epoch - 60))" >plant.state
/tmp/retro_schedule full.yaml audit-plant.jsonl plant.state 1 | tee plant.out
ls -l plant.state plant.state.tmp victim.txt
check "planted link left the victim unchanged" "victim-bytes" "$(cat victim.txt)"
check "state file is a regular file" "regular file" "$(stat -c %F plant.state)"

echo "--- a hard-linked state file is refused"
printf 'tenant-a %s' "$((now_epoch - 60))" >linked.state
ln linked.state linked.second
/tmp/retro_schedule full.yaml audit-linked.jsonl linked.state 1 | tee linked.out
grep -q '^start state_unreadable$' linked.out && echo "PASS hard-linked state named" || { echo "FAIL hard link accepted"; failures=$((failures + 1)); }

echo "--- the reader is the loader: refused at start and at reload, old settings kept"
sed "s/user: retro_reader/user: $CLICKHOUSE_USER/" full.yaml >equal.yaml
if /tmp/retro_schedule equal.yaml audit-equal.jsonl equal.state 1 >equal.out 2>equal.err; then
    echo "FAIL equal reader accepted at start"; failures=$((failures + 1))
else
    grep -q 'ReaderIsLoader' equal.err && echo "PASS refused at start: $(head -c 200 equal.err)" || { echo "FAIL not named"; failures=$((failures + 1)); }
fi
cp full.yaml equal-reload.yaml
/tmp/retro_schedule equal-reload.yaml audit-equal-reload.jsonl equal-reload.state 4 >equal-reload.out &
equal_pid=$!
sleep 2
sed -i "s/user: retro_reader/user: $CLICKHOUSE_USER/" equal-reload.yaml
sleep 3
wait "$equal_pid"
grep -ci 'denied\|refus' audit-equal-reload.jsonl | sed 's/^/audited refusals: /'
grep -qi 'denied\|refus' audit-equal-reload.jsonl && echo "PASS reload refused and audited" || { echo "FAIL equal reader reload not audited"; failures=$((failures + 1)); }
grep -c 'done' equal-reload.out | sed 's/^/rounds on the old settings: /'

echo "--- foreign dictionary: a second tenant in the shared table"
printf 'feeds: []\n' >other-tenant.yaml
{ printf 'feeds:\n  - name: lab\n    format: crowdsec\n    path: unused.txt\nclickhouse:\n'; clickhouse_block "$CLICKHOUSE_USER" ch.pw tenant-b; } >other-tenant.yaml
head -1 iocs.jsonl >iocs-b.jsonl
/tmp/intel_load other-tenant.yaml iocs-b.jsonl
if /tmp/retro_run reader.yaml ostyr events "$(date -u -d '-10 minutes' +%FT%TZ)" "$(date -u +%FT%TZ)" >foreign.out 2>foreign.err; then
    echo "FAIL foreign dictionary accepted"; failures=$((failures + 1))
else
    cat foreign.err | head -3
    grep -q 'ForeignDictionary' foreign.err && echo "PASS ForeignDictionary" || { echo "FAIL foreign_dictionary not named"; failures=$((failures + 1)); }
fi
check "no alert was added by the refused run" "7" "$(sql "SELECT count(*) FROM alerts WHERE tenant = 'tenant-a' AND rule_id = 'intel.retro_match.ip'")"

echo "--- forced timeout: code of the slow view"
ch "ALTER TABLE ostyr.iocs DELETE WHERE tenant = 'tenant-b' SETTINGS mutations_sync = 2" >/dev/null
if /tmp/retro_run reader.yaml ostyr events_slow "$(date -u -d '-10 minutes' +%FT%TZ)" "$(date -u +%FT%TZ)" seconds=1 >slow.out 2>slow.err; then
    echo "FAIL slow view not refused"; failures=$((failures + 1))
else
    head -3 slow.err
fi
curl -sS -D - -o /dev/null --cacert /etc/ostyr-lab/ca.pem -u "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" "$url/?max_execution_time=1" \
    --data-binary "SELECT count() FROM ostyr.events_slow" | grep -i 'x-clickhouse-exception-code'

echo "--- a reload that changes the tenant saves under the new tenant (the table then holds tenant-b only)"
ch "ALTER TABLE ostyr.iocs DELETE WHERE 1 SETTINGS mutations_sync = 2" >/dev/null
/tmp/intel_load other-tenant.yaml iocs-b.jsonl
sleep 3
cp full.yaml tenant-reload.yaml
rm -f tenant-reload.state
/tmp/retro_schedule tenant-reload.yaml audit-tenant-reload.jsonl tenant-reload.state 16 >tenant-reload.out &
tenant_pid=$!
sleep 3
sed -i '/^retro:/,$ s/tenant: tenant-a/tenant: tenant-b/' tenant-reload.yaml
wait "$tenant_pid"
cat tenant-reload.out
cat tenant-reload.state; echo
check "state file holds the new tenant" "tenant-b" "$(cut -d' ' -f1 tenant-reload.state)"
/tmp/retro_schedule full.yaml audit-tenant-back.jsonl tenant-reload.state 1 | tee tenant-back.out
grep -q '^start state_other_tenant$' tenant-back.out && echo "PASS restart under tenant-a names state_other_tenant" || { echo "FAIL other tenant not named"; failures=$((failures + 1)); }

echo "failures: $failures"
exit "$failures"
REMOTE
