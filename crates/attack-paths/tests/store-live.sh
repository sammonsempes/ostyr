#!/usr/bin/env bash
# Usage: [MUTANT=nolock] crates/attack-paths/tests/store-live.sh <lab-state-dir>
# Live check of the attack path report store on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the attack_paths_store example, built for
# musl, runs on the client VM against a scratch database; psql and pgbench read and load the real state. MUTANT=nolock replaces the store function by one
# without its advisory lock line and the race section must then store more than the cap.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: store-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
binary="$here/target/x86_64-unknown-linux-musl/release/examples/attack_paths_store"
[[ -x "$binary" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p attack-paths --example attack_paths_store" >&2; exit 2; }

database="ap_store_$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true' EXIT

scp "${ssh_options[@]}" "$binary" "$client_user@$client_address:/tmp/attack_paths_store"
scp "${ssh_options[@]}" "$here/crates/attack-paths/migrations/attack_paths_0001.sql" "$client_user@$client_address:/tmp/attack_paths_0001.sql"
scp -3 "${ssh_options[@]}" "$datastore_user@$datastore_address:/usr/lib/postgresql/16/bin/pgbench" "$client_user@$client_address:/tmp/pgbench"
remote_status=0
ssh "${ssh_options[@]}" "$client_user@$client_address" "DATABASE=$database MUTANT=${MUTANT:-none} bash -s" <<'REMOTE' || remote_status=$?
set -euo pipefail
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf '%s' "$POSTGRES_PASSWORD" >"$work/password"
chmod 600 "$work/password"
cat >"$work/pg.yaml" <<YAML
host: $DATASTORE_DOMAIN
port: $POSTGRES_PORT
database: $DATABASE
user: $POSTGRES_USER
password_file: $work/password
ca_file: /etc/ostyr-lab/ca.pem
YAML
cat >"$work/graph.yaml" <<YAML
nodes:
  - {id: ws1, kind: workstation, entry_point: true}
  - {id: ws2, kind: workstation, entry_point: true}
  - {id: grp, kind: group}
  - {id: dc, kind: domain_controller, critical: true}
edges:
  - {from: ws1, to: grp, relation: member_of}
  - {from: ws2, to: grp, relation: member_of}
  - {from: grp, to: dc, relation: admin_to}
YAML
export PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full PGSSLROOTCERT=/etc/ostyr-lab/ca.pem
sql() { psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" -c "$1"; }
store() { /tmp/attack_paths_store "$@"; }
app() { store "$1" "$work/pg.yaml" "${@:2}"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
refused() { "$@" >/dev/null 2>&1 && echo stored || echo refused; }
NOW=2026-11-23T10:00:00Z

check "migrate applies the migration" "applied [\"attack_paths_0001\"]" "$(app migrate)"
check "a second migrate applies nothing" "applied []" "$(app migrate)"
check "the function pins its search path" "{\"search_path=pg_catalog, public, pg_temp\"}" "$(sql "SELECT proconfig::text FROM pg_proc WHERE proname = 'attack_path_report_store'")"

if [[ "$MUTANT" == nolock ]]; then
    sql "DROP FUNCTION attack_path_report_store(text, text, text, text, text, boolean, boolean, bigint, bigint)"
    grep -v "pg_advisory_xact_lock" /tmp/attack_paths_0001.sql | awk '/CREATE FUNCTION/ {on = 1} on {print}' | psql -X -q -v ON_ERROR_STOP=1 \
        -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" -f -
fi

echo "--- store, re-store, list, get"
check "first store" "Stored { id: 1 }" "$(app store 5 acme "$work/graph.yaml" $NOW)"
check "the same graph again is already stored" "AlreadyStored { id: 1 }" "$(app store 5 acme "$work/graph.yaml" 2026-11-24T10:00:00Z)"
check "a cut search is a different report and keeps its flag" "Stored { id: 2 }" "$(app store 5 acme "$work/graph.yaml" $NOW 1)"
echo "psql read-back:"
sql "SELECT tenant, id, left(graph_digest, 12), generated AT TIME ZONE 'UTC', left(digest, 12), octet_length(body), truncated, budget_reached, unsearched_count FROM attack_path_report ORDER BY id"
check "the cut report row says truncated and one entry unsearched" "t|f|1" "$(sql "SELECT truncated::text || '|' || budget_reached::text || '|' || unsearched_count FROM attack_path_report WHERE id = 2" | sed 's/true/t/;s/false/f/g')"
app list acme 10
check "list has two rows newest first, with the flags" "2" "$(app list acme 10 | wc -l)"
check "the first listed row is id 2, truncated" "1" "$(app list acme 10 | head -1 | grep -c 'id: 2,.*truncated: true')"
check "get returns the document with the flag" "1" "$(app get acme 2 | grep -c '"truncated":true')"
check "a cross-tenant get finds nothing" "not found" "$(app get other 2)"
check "a cross-tenant list is empty" "0" "$(app list other 10 | wc -l)"
check "a refused tenant name is refused" "refused" "$(refused app store 5 -x "$work/graph.yaml" $NOW)"
check "year 10000 in UTC is refused" "refused" "$(refused app store 5 acme "$work/graph.yaml" 9999-12-31T23:00:00-02:00)"
check "+10000 is refused" "refused" "$(refused app store 5 acme "$work/graph.yaml" +10000-01-01T00:00:00Z)"
check "year 0 is refused" "refused" "$(refused app store 5 acme "$work/graph.yaml" 0000-01-01T00:00:00Z)"
check "nothing was stored by the refusals" "2" "$(sql "SELECT count(*) FROM attack_path_report")"
check "9999-12-31T23:59:59Z is stored and read back" "9999-12-31T23:59:59Z" "$(app store 5 edge "$work/graph.yaml" 9999-12-31T23:59:59Z >/dev/null; app list edge 1 | sed 's/.*generated: "\([^"]*\)".*/\1/')"

echo "--- a tampered body"
sql "UPDATE attack_path_report SET body = replace(body, '\"truncated\":true', '\"truncated\":false') WHERE id = 2"
check "get refuses the edited body by digest" "the stored report no longer matches its digest" "$(app get acme 2 2>&1 || true)"
sql "UPDATE attack_path_report SET body = replace(body, '\"truncated\":false', '\"truncated\":true') WHERE id = 2"
check "restored, get works again" "1" "$(app get acme 2 | grep -c '"truncated":true')"
sql "UPDATE attack_path_report SET truncated = false WHERE id = 2"
check "a changed flag column is a named mismatch" "the stored columns disagree with the stored body" "$(app get acme 2 2>&1 || true)"
sql "UPDATE attack_path_report SET truncated = true WHERE id = 2"

echo "--- the CHECK limits"
check "a bad digest is refused by the table" "refused" "$(refused sql "INSERT INTO attack_path_report (tenant, graph_digest, generated, digest, body, truncated, budget_reached, unsearched_count) VALUES ('c', 'x', now(), 'x', '{}', false, false, 0)")"
check "year 10000 is refused by the table" "refused" "$(refused sql "INSERT INTO attack_path_report (tenant, graph_digest, generated, digest, body, truncated, budget_reached, unsearched_count) VALUES ('c', repeat('a', 64), '10000-01-01 00:00:00+00', repeat('a', 64), '{}', false, false, 0)")"
check "a body over 1 MiB is refused by the table" "refused" "$(refused sql "INSERT INTO attack_path_report (tenant, graph_digest, generated, digest, body, truncated, budget_reached, unsearched_count) VALUES ('c', repeat('a', 64), now(), repeat('a', 64), repeat('x', 1048577), false, false, 0)")"
check "a negative count is refused by the table" "refused" "$(refused sql "INSERT INTO attack_path_report (tenant, graph_digest, generated, digest, body, truncated, budget_reached, unsearched_count) VALUES ('c', repeat('a', 64), now(), repeat('a', 64), '{}', false, false, -1)")"

echo "--- 20 clients at cap 5 on 5 fresh tenants"
cat >"$work/race.sql" <<'PGB'
SELECT outcome FROM attack_path_report_store(:tenant, md5(random()::text) || md5(random()::text), now()::text, md5(random()::text) || md5(random()::text), '{}', false, false, 0, 5);
PGB
for tenant in r1 r2 r3 r4 r5; do
    /tmp/pgbench -n -c 20 -j 4 -t 3 -f "$work/race.sql" -D "tenant='$tenant'" -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" "$DATABASE" >"$work/race-$tenant.out" 2>&1
done
grep -h "error\|processed" "$work"/race-r?.out || true
counts="$(sql "SELECT string_agg(n::text, ',' ORDER BY tenant) FROM (SELECT tenant, count(*) AS n FROM attack_path_report WHERE tenant LIKE 'r_' GROUP BY tenant) c")"
echo "rows per tenant after the race: $counts"
if [[ "$MUTANT" == nolock ]]; then
    check "mutant: the race stores more than the cap on some tenant" "1" "$(awk -F, '{for (i = 1; i <= NF; i++) if ($i > 5) {print 1; exit}} END {}' <<<"$counts")"
else
    check "exactly the cap is stored per tenant" "5,5,5,5,5" "$counts"
fi

echo "--- plan under stale statistics, 600 rows of a new tenant, no ANALYZE"
if [[ "$MUTANT" == none ]]; then
    sql "INSERT INTO attack_path_report (tenant, graph_digest, generated, digest, body, truncated, budget_reached, unsearched_count) SELECT 'big', md5(g::text) || md5(g::text), now(), md5(g::text) || md5(g::text), repeat('x', 1000), false, false, 0 FROM generate_series(1, 600) g"
    psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" <<'SQL'
SET plan_cache_mode = force_generic_plan;
PREPARE list_plan(text, text) AS SELECT id::text, graph_digest, digest, octet_length(body)::text, truncated::text, budget_reached::text, unsearched_count::text FROM attack_path_report WHERE tenant = $1 ORDER BY attack_path_report.id DESC LIMIT $2::text::bigint;
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF) EXECUTE list_plan('big', '100');
PREPARE get_plan(text, text) AS SELECT graph_digest, digest, truncated::text, body FROM attack_path_report WHERE tenant = $1 AND id = $2::text::bigint;
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF) EXECUTE get_plan('big', '300');
SQL
    echo "autoanalyze before the plans: $(sql "SELECT coalesce(last_autoanalyze::text, 'never') || '/' || coalesce(last_analyze::text, 'never') FROM pg_stat_user_tables WHERE relname = 'attack_path_report'")"
fi
echo "failures=$failures"
exit "$failures"
REMOTE
echo "remote_status=$remote_status"
exit "$remote_status"
