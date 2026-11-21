#!/bin/bash
# Run as root on the datastore-pair client VM: live checks of the coverage report (T660).
# Usage: live-coverage.sh <bin-dir with hunt_coverage and hunt_state> <packs-dir> <big-rows> <deadline-ms>
set -euo pipefail
BIN=$1
PACKS=$2
BIG_ROWS=$3
DEADLINE_MS=$4
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
cover() { "$BIN/hunt_coverage" "$WORK/pg.yaml" "$PACKS" "$@"; }
FROM=1000000
TO=2000000
INSIDE=1500000
BEACON=beaconing-regular-interval
RARE=rare-parent-child
"$BIN/hunt_state" "$WORK/pg.yaml" get tcovsmall "$BEACON" >/dev/null
sql -c "DELETE FROM hunt_pack_findings WHERE tenant LIKE 'tcov%'" -c "DELETE FROM hunt_pack_runs WHERE tenant LIKE 'tcov%'"

echo "--- negative rows only: not_hunted, rows stay in skipped"
sql -c "INSERT INTO hunt_pack_findings (tenant, pack_id, window_start, window_end, matches, max_matches, found_at) VALUES \
    ('tcovsmall', '$RARE', 1, $INSIDE, -5, 0, now()), ('tcovsmall', '$BEACON', 1, $INSIDE, 3, 0, now())"
cover tcovsmall "$FROM" "$TO" | grep -E '"(technique|state|findings|skipped)"'

echo "--- a run row ending in the period: hunted_clear for the negative-only pack"
"$BIN/hunt_state" "$WORK/pg.yaml" set tcovsmall "$RARE" "$INSIDE" >/dev/null
cover tcovsmall "$FROM" "$TO" | grep -E '"(technique|state|findings|skipped)"'

echo "--- a hand-built id x,y is refused before any statement"
if cover tcovsmall "$FROM" "$TO" 10000 'x,y'; then echo "UNEXPECTED success"; exit 1; fi

echo "--- a big tenant reaches a lowered statement deadline, a small one does not"
sql -c "INSERT INTO hunt_pack_findings (tenant, pack_id, window_start, window_end, matches, max_matches, found_at) \
    SELECT 'tcovbig', '$BEACON', 1, $FROM + g, 1, 0, now() FROM generate_series(1, $BIG_ROWS) g"
sql -c "INSERT INTO hunt_pack_findings (tenant, pack_id, window_start, window_end, matches, max_matches, found_at) \
    SELECT 'tcovmid', '$BEACON', 1, g * 100, 1, 0, now() FROM generate_series(1, 50000) g"
sql -c "ANALYZE hunt_pack_findings"
echo "--- the loaded findings arm uses hunt_pack_findings_listable"
PLAN=$(sql -c "SET enable_seqscan = on" -c "EXPLAIN (COSTS OFF) SELECT 0, pack_id, count(*) FROM hunt_pack_findings WHERE tenant = 'tcovmid' AND window_end >= $FROM \
    AND window_end < $TO AND octet_length(pack_id) <= 64 AND pack_id = ANY(string_to_array('$BEACON,$RARE', ',')) GROUP BY pack_id")
echo "$PLAN" | grep -E 'Index|Seq|Bitmap'
echo "$PLAN" | grep -q hunt_pack_findings_listable
echo "--- the same without the predicate (old statement)"
sql -c "SET enable_seqscan = on" -c "EXPLAIN (COSTS OFF) SELECT 0, pack_id, count(*) FROM hunt_pack_findings WHERE tenant = 'tcovmid' AND window_end >= $FROM \
    AND window_end < $TO AND pack_id = ANY(string_to_array('$BEACON,$RARE', ',')) GROUP BY pack_id" | grep -E 'Index|Seq|Bitmap'

if cover tcovbig "$FROM" "$TO" "$DEADLINE_MS"; then echo "UNEXPECTED success"; exit 1; fi
cover tcovsmall "$FROM" "$TO" "$DEADLINE_MS" | grep -c '"state"'
cover tcovbig "$FROM" "$TO" | grep -E '"(findings|state)"'
sql -c "DELETE FROM hunt_pack_findings WHERE tenant LIKE 'tcov%'" -c "DELETE FROM hunt_pack_runs WHERE tenant LIKE 'tcov%'"
