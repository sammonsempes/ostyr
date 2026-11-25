#!/bin/bash
# Run as root on the datastore-pair client VM: live checks of the statistical hunts (T908).
# Usage: live-stat.sh <bin-dir with ostyr-hunt and hunt_state> <events-ddl.sql: the first statement creates `events`>
set -euo pipefail
BIN=$1
DDL=$2
ENV_FILE=/etc/ostyr-lab/datastore.env
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
set -a
. "$ENV_FILE"
set +a
umask 077
printf '%s' "$POSTGRES_PASSWORD" >"$WORK/pg.password"
printf '%s' "$CLICKHOUSE_PASSWORD" >"$WORK/ch.password"
cat >"$WORK/pg.yaml" <<EOF
host: $DATASTORE_DOMAIN
port: $POSTGRES_PORT
database: $POSTGRES_DATABASE
user: $POSTGRES_USER
password_file: $WORK/pg.password
ca_file: $DATASTORE_CA
EOF
cat >"$WORK/ch.yaml" <<EOF
url: https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT
user: $CLICKHOUSE_USER
password_file: $WORK/ch.password
ca_file: $DATASTORE_CA
timeout_ms: 20000
EOF
mkdir "$WORK/packs"
sql() { PGPASSWORD=$POSTGRES_PASSWORD PGSSLROOTCERT=$DATASTORE_CA PGSSLMODE=verify-full psql -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -v ON_ERROR_STOP=1 -At "$@"; }
clickhouse() { curl --fail --silent --show-error --cacert "$DATASTORE_CA" --user "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" --data-binary "$1" "https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT/"; }
clickhouse "$(sed -n '1,/^;$/p' "$DDL" | sed '$d')"
clickhouse "ALTER TABLE events DELETE WHERE tenant LIKE 'tis%' SETTINGS mutations_sync = 2"

END=$(( $(date +%s) / 3600 * 3600 ))
START=$(( END - 3600 ))
row() { printf '{"@timestamp":"%s","tenant":"%s","host.name":"%s","process.executable":"%s","destination.ip":"%s","event.category":["%s"]}\n' \
    "$(date -u -d "@$1" '+%Y-%m-%d %H:%M:%S')" "$2" "$3" "$4" "$5" "$6"; }
{
    for host in h1 h2 h3 h4; do
        row $((START + 100)) tisoa "$host" /bin/bash 0.0.0.0 process
        row $((START + 110)) tisob "$host" /bin/bash 0.0.0.0 process
    done
    row $((START + 200)) tisoa h1 /opt/rare-a.exe 0.0.0.0 process
    row $((START + 210)) tisob h9 /opt/rare-b1.exe 0.0.0.0 process
    row $((START + 220)) tisob h8 /opt/rare-b2.exe 0.0.0.0 process
    for i in $(seq 0 19); do
        row $((START + 300 + 60 * i)) tisoa h7 '' 10.0.0.9 network
        row $((START + 300 + 60 * i)) tisob h6 '' 10.0.0.8 network
    done
    for offset in 0 5 90 100 400 410 900 1000 1500 1510 2000 2900; do
        row $((START + 300 + offset)) tisob h5 '' 10.0.0.7 network
        row $((START + 300 + offset)) tisoa h5 '' 10.0.0.7 network
    done
} >"$WORK/events.jsonl"
curl --fail --silent --show-error --cacert "$DATASTORE_CA" --user "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" --data-binary "@$WORK/events.jsonl" \
    "https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT/?query=INSERT%20INTO%20events%20(%60%40timestamp%60%2C%20tenant%2C%20%60host.name%60%2C%20%60process.executable%60%2C%20%60destination.ip%60%2C%20%60event.category%60)%20FORMAT%20JSONEachRow"
echo "--- seeded rows per tenant"
clickhouse "SELECT tenant, count() FROM events WHERE tenant LIKE 'tis%' GROUP BY tenant ORDER BY tenant FORMAT TabSeparated"

WINDOW='AND `@timestamp` >= {window_start:DateTime64(3)} AND `@timestamp` < {window_end:DateTime64(3)}'
write_hunt() {
    cat >"$WORK/hunt.yaml" <<EOF
pg_settings: $WORK/pg.yaml
clickhouse_settings: $WORK/ch.yaml
packs_dir: $WORK/packs
audit_file: $WORK/audit.log
tenants: [tisoa, tisob, tisoc]
tick_seconds: 10
stat_hunts:
  - id: rare-process
    statistic:
      rarity:
        max_entities: 1
    query: >-
      SELECT \`host.name\`, \`process.executable\` FROM events WHERE tenant = {tenant:String} $WINDOW AND has(\`event.category\`, 'process')
    schedule_seconds: 3600
    window_seconds: 3600
    cost: {max_rows: 100000, max_seconds: 10, max_bytes_read: 100000000}
    max_rows: 1000
  - id: beacon
    statistic:
      beaconing:
        min_regularity_ppm: 900000
    query: >-
      SELECT concat(\`host.name\`, '>', \`destination.ip\`), toUnixTimestamp(\`@timestamp\`) FROM events WHERE tenant = {tenant:String} $WINDOW
      AND has(\`event.category\`, 'network')
    schedule_seconds: 3600
    window_seconds: 3600
    cost: {max_rows: 100000, max_seconds: 10, max_bytes_read: 100000000}
    max_rows: 1000
  - id: tiny
    statistic:
      rarity:
        max_entities: 1
    query: >-
      SELECT \`host.name\`, \`process.executable\` FROM events WHERE tenant = {tenant:String} $WINDOW AND has(\`event.category\`, 'process')
    schedule_seconds: 3600
    window_seconds: 3600
    cost: {max_rows: 100000, max_seconds: 10, max_bytes_read: 100000000}
    max_rows: 3
EOF
}
write_hunt
reset_state() { sql -c "DELETE FROM hunt_pack_findings WHERE tenant LIKE 'tis%'" -c "DELETE FROM hunt_pack_runs WHERE tenant LIKE 'tis%'" >/dev/null; }
"$BIN/hunt_state" "$WORK/pg.yaml" get tisoa x >/dev/null
reset_state

if [ -n "${ONLY_PROFILE_ATTACK:-}" ]; then
echo "--- attack: a profile that changed a setting is refused before the query (ONLY_PROFILE_ATTACK=1 after adding one to the ClickHouse user profile)"
timeout 25 "$BIN/ostyr-hunt" "$WORK/hunt.yaml" 2>&1 | grep -v ' DEBUG ' | head -12 || true
echo "findings after the refused rounds:"
sql -c "SELECT count(*) FROM hunt_pack_findings WHERE tenant LIKE 'tis%'"
else
echo "--- one round of ostyr-hunt (SIGTERM after 25 s)"
timeout 25 "$BIN/ostyr-hunt" "$WORK/hunt.yaml" 2>&1 | grep -v ' DEBUG ' | head -30 || true
for tenant in tisoa tisob tisoc; do
    echo "--- findings of $tenant (end, pack, start, matches, baseline)"
    "$BIN/hunt_state" "$WORK/pg.yaml" findings "$tenant"
done
echo "--- rows in PostgreSQL by tenant and pack"
sql -c "SELECT tenant, pack_id, matches, max_matches FROM hunt_pack_findings WHERE tenant LIKE 'tis%' ORDER BY tenant, pack_id"
echo "--- run state"
sql -c "SELECT tenant, pack_id FROM hunt_pack_runs WHERE tenant LIKE 'tis%' ORDER BY tenant, pack_id"

echo "--- attack: a hunt with a SETTINGS clause that lifts the cost pins is refused at load"
sed -i 's/AND has(`event.category`, .network.)/AND has(`event.category`, '"'"'network'"'"') SETTINGS max_rows_to_read = 0/' "$WORK/hunt.yaml"
reset_state
timeout 25 "$BIN/ostyr-hunt" "$WORK/hunt.yaml" 2>&1 | grep -v ' DEBUG ' | grep -i 'settings\|failed' | head -6 || true
fi
echo "--- done"
