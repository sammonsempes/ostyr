#!/bin/bash
# Run as root on the datastore-pair client VM: the two-session finding race of T922.
# Usage: live-finding-race.sh <bin-dir with hunt_state>
# Session A inserts a finding and holds its transaction; session B runs FINDING_SQL for a different finding of the same key and must wait for A,
# then answer 1 (conflict); an identical finding answers 2 (replay), a new key 0 (inserted).
# tests/findings checks that FINDING_SQL below is the text of the crate constant.
set -euo pipefail
BIN=$1
ENV_FILE=/etc/ostyr-lab/datastore.env
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
set -a
. "$ENV_FILE"
set +a
umask 077
printf '%s' "$POSTGRES_PASSWORD" >"$WORK/password"
cat >"$WORK/pg.yaml" <<EOF
host: $DATASTORE_DOMAIN
port: $POSTGRES_PORT
database: $POSTGRES_DATABASE
user: $POSTGRES_USER
password_file: $WORK/password
ca_file: $DATASTORE_CA
EOF
sql() { PGPASSWORD=$POSTGRES_PASSWORD PGSSLROOTCERT=$DATASTORE_CA PGSSLMODE=verify-full psql -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -v ON_ERROR_STOP=1 -At "$@"; }
FINDING_SQL='INSERT INTO hunt_pack_findings (tenant, pack_id, window_start, window_end, matches, max_matches, found_at) VALUES ($1, $2, $3, $4, $5, $6, now()) ON CONFLICT (tenant, pack_id, window_end) DO UPDATE SET found_at = hunt_pack_findings.found_at RETURNING CASE WHEN hunt_pack_findings.xmax = 0 THEN 0 WHEN (window_start, matches, max_matches) = ($3, $5, $6) THEN 2 ELSE 1 END::bigint'
PREPARE="PREPARE f(text, text, bigint, bigint, bigint, bigint) AS $FINDING_SQL"
"$BIN/hunt_state" "$WORK/pg.yaml" get trace rarity.tiny.bound >/dev/null
sql -c "DELETE FROM hunt_pack_findings WHERE tenant LIKE 'trace%'"

echo "--- no conflict: inserted (0), identical replay (2), different baseline only (1), different matches (1)"
sql -c "$PREPARE" -c "EXECUTE f('trace0', 'p', 1, 100, 5, 0)" -c "EXECUTE f('trace0', 'p', 1, 100, 5, 0)" \
    -c "EXECUTE f('trace0', 'p', 1, 100, 5, 7)" -c "EXECUTE f('trace0', 'p', 1, 100, 6, 0)" -c "EXECUTE f('trace0', 'p', 2, 100, 5, 0)"

echo "--- session A inserts matches 999 and holds the transaction, session B (matches 3) waits on the conflict"
sql -c "INSERT INTO hunt_pack_findings (tenant, pack_id, window_start, window_end, matches, max_matches, found_at) VALUES ('trace1', 'p', 1, 100, 999, 0, now()); SELECT pg_sleep(8)" >"$WORK/a.out" 2>&1 &
APID=$!
BEGIN_WAIT=0
until [ "$(sql -c "SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%pg_sleep(8)%' AND pid <> pg_backend_pid()")" -ge 1 ] || [ "$BEGIN_WAIT" -ge 30 ]; do
    BEGIN_WAIT=$((BEGIN_WAIT + 1))
    sleep 1
done
sql -c "$PREPARE" -c "EXECUTE f('trace1', 'p', 1, 100, 3, 0)" >"$WORK/b.out" 2>&1 &
BPID=$!
WAITING=0
ATTEMPT=0
until [ "$WAITING" -ge 1 ] || [ "$ATTEMPT" -ge 30 ]; do
    WAITING=$(sql -c "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%EXECUTE f(%'")
    ATTEMPT=$((ATTEMPT + 1))
    sleep 1
done
echo "waiting sessions: $WAITING"
wait "$APID"
wait "$BPID"
echo "session B answered:"
cat "$WORK/b.out"
grep -qx 1 "$WORK/b.out"
echo "stored: $(sql -c "SELECT matches FROM hunt_pack_findings WHERE tenant = 'trace1'")"
echo "--- the old statement (snapshot read) for the same race returns no row"
OLD='WITH inserted AS (INSERT INTO hunt_pack_findings (tenant, pack_id, window_start, window_end, matches, max_matches, found_at) VALUES ($1, $2, $3, $4, $5, $6, now()) ON CONFLICT (tenant, pack_id, window_end) DO NOTHING RETURNING 0::bigint AS code) SELECT code FROM inserted UNION ALL SELECT 1::bigint FROM hunt_pack_findings WHERE tenant = $1 AND pack_id = $2 AND window_end = $4 AND (window_start, matches, max_matches) <> ($3, $5, $6)'
sql -c "DELETE FROM hunt_pack_findings WHERE tenant = 'trace2'"
sql -c "INSERT INTO hunt_pack_findings (tenant, pack_id, window_start, window_end, matches, max_matches, found_at) VALUES ('trace2', 'p', 1, 100, 999, 0, now()); SELECT pg_sleep(8)" >"$WORK/a2.out" 2>&1 &
APID=$!
sleep 3
sql -c "PREPARE g(text, text, bigint, bigint, bigint, bigint) AS $OLD" -c "EXECUTE g('trace2', 'p', 1, 100, 3, 0)" >"$WORK/b2.out" 2>&1
wait "$APID"
echo "old statement answered: [$(cat "$WORK/b2.out")]"
sql -c "DELETE FROM hunt_pack_findings WHERE tenant LIKE 'trace%'"
