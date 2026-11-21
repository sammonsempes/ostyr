#!/usr/bin/env bash
# Usage: crates/cloud-posture/tests/store-live.sh <lab-state-dir>
# Live check of the posture findings store on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the posture_store example, built for musl
# (cargo build --release --target x86_64-unknown-linux-musl -p cloud-posture --example posture_store), runs on the client VM against a scratch database
# and psql reads the real state back: migration, tenant isolation, the row cap at commit, NUL and duplicate handling, the regexes against edge inputs,
# the plans under stale statistics and the time of a 100 000 row run.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: store-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
binary="$here/target/x86_64-unknown-linux-musl/release/examples/posture_store"
[[ -x "$binary" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p cloud-posture --example posture_store" >&2; exit 2; }
migration="$here/crates/cloud-posture/migrations/posture_0001.sql"

database="posture_live_$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true' EXIT

scp "${ssh_options[@]}" "$binary" "$client_user@$client_address:/tmp/posture_store"
reference="$(grep -o "check_id ~ '[^']*'" "$migration" | head -1 | sed "s/check_id ~ '//; s/'$//")"
spaced="$(grep -o "resource_uid ~ '[^']*'" "$migration" | head -1 | sed "s/resource_uid ~ '//; s/'$//")"
provider="$(grep -o "provider ~ '[^']*'" "$migration" | head -1 | sed "s/provider ~ '//; s/'$//")"
ssh "${ssh_options[@]}" "$client_user@$client_address" "DATABASE=$database REFERENCE='$reference' SPACED='$spaced' PROVIDER='$provider' bash -s" <<'REMOTE'
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
export PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full PGSSLROOTCERT=/etc/ostyr-lab/ca.pem
sql() { psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" -c "$1"; }
posture() { /tmp/posture_store "$work/pg.yaml" "$@" 2>&1; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
NOW=1700000000000000
rows() { sql "SELECT count(*) FROM cloud_posture_findings WHERE tenant = '$1' AND account = '$2'"; }

posture migrate
posture migrate
check "migrations recorded once" "1" "$(sql "SELECT count(*) FROM schema_migrations WHERE namespace = 'posture'")"
check "function and tables exist" "1|1|1" "$(sql "SELECT (SELECT count(*) FROM pg_proc WHERE proname = 'posture_replace_run') || '|' || (SELECT count(*) FROM pg_class WHERE relname = 'cloud_posture_findings') || '|' || (SELECT count(*) FROM pg_class WHERE relname = 'cloud_posture_runs')")"
check "function settings pinned" '{"search_path=pg_catalog, public, pg_temp",enable_seqscan=off,enable_bitmapscan=off,jit=off}' "$(sql "SELECT proconfig FROM pg_proc WHERE proname = 'posture_replace_run'")"

echo "--- tenant isolation, same account id in two tenants"
check "tenant a stores 5" "Ok(RunOutcome { stored: 5, store_refused: 0, duplicate: 0 })" "$(posture bulk a acc1 run1 $NOW 5 a1)"
check "tenant b stores 3" "Ok(RunOutcome { stored: 3, store_refused: 0, duplicate: 0 })" "$(posture bulk b acc1 run1 $NOW 3 b1)"
check "a rows" 5 "$(rows a acc1)"
check "b rows" 3 "$(rows b acc1)"
posture bulk b acc1 run2 $NOW 2 b2 >/dev/null
check "b replaced its own rows only" "5|2" "$(rows a acc1)|$(rows b acc1)"
check "run rows" "a|acc1|run1|5;b|acc1|run2|2" "$(sql "SELECT string_agg(tenant || '|' || account || '|' || run_id || '|' || items, ';' ORDER BY tenant) FROM cloud_posture_runs")"

echo "--- two findings with one uid and different resource uid"
check "both stored" "Ok(RunOutcome { stored: 2, store_refused: 0, duplicate: 0 })" "$(posture twin t acc1 run1 $NOW)"
check "two rows" 2 "$(rows t acc1)"

echo "--- NUL in a detail"
check "one refused, rest stored" "Ok(RunOutcome { stored: 4, store_refused: 1, duplicate: 0 })" "$(posture bulk n acc1 run1 $NOW 4 nn nul)"
check "run row counts" "4|1|1" "$(sql "SELECT items || '|' || store_refused || '|' || refused_fail FROM cloud_posture_runs WHERE tenant = 'n'")"
check "no NUL stored" 0 "$(sql "SELECT count(*) FROM cloud_posture_findings WHERE tenant = 'n' AND detail LIKE '%bad%'")"

echo "--- cap at commit: account A 150000 rows then account B 50001"
posture bulk c accA run1 $NOW 150000 ca
check "A rows" 150000 "$(rows c accA)"
check "B refused" "Err(TenantCap { cap: 200000, items: 50001, others: 150001 })" "$(posture bulk c accB run1 $NOW 50001 cb)"
check "A intact" 150000 "$(rows c accA)"
check "B has no rows" 0 "$(rows c accB)"
check "B run row shows the refusal" "50001|0" "$(sql "SELECT refused_items || '|' || items FROM cloud_posture_runs WHERE tenant = 'c' AND account = 'accB'")"
check "B with 49999 is refused too: the run row of A counts" "Err(TenantCap { cap: 200000, items: 49999, others: 150001 })" "$(posture bulk c accB run3 $NOW 49999 cb)"
check "B with 49998 fits" "Ok(RunOutcome { stored: 49998, store_refused: 0, duplicate: 0 })" "$(posture bulk c accB run2 $NOW 49998 cb)"
check "B refusal cleared" "49998|0" "$(sql "SELECT items || '|' || refused_items FROM cloud_posture_runs WHERE tenant = 'c' AND account = 'accB'")"
check "tenant d unaffected by c" "Ok(RunOutcome { stored: 3, store_refused: 0, duplicate: 0 })" "$(posture bulk d accA run1 $NOW 3 da)"

echo "--- a run of 100000 rows: time"
start=$(date +%s.%N)
check "100000 rows" "Ok(RunOutcome { stored: 100000, store_refused: 0, duplicate: 0 })" "$(posture bulk e accA run1 $NOW 100000 ea)"
end=$(date +%s.%N)
echo "100000 rows replaced in $(awk -v a="$start" -v b="$end" "BEGIN {print b - a}") s (includes the process start and the document build)"
start=$(date +%s.%N)
posture bulk e accA run2 $NOW 100000 ea >/dev/null
end=$(date +%s.%N)
echo "100000 rows replaced again in $(awk -v a="$start" -v b="$end" "BEGIN {print b - a}") s"

echo "--- plans under stale statistics (autovacuum off, no ANALYZE, a new tenant with 100000 rows)"
sql "ALTER TABLE cloud_posture_findings SET (autovacuum_enabled = false)"
sql "ALTER TABLE cloud_posture_runs SET (autovacuum_enabled = false)"
sql "DELETE FROM cloud_posture_findings WHERE tenant = 'e'"
sql "DELETE FROM cloud_posture_runs WHERE tenant = 'e'"
posture bulk f accA run1 $NOW 100000 fa >/dev/null
sql "SELECT 'analyzed: ' || coalesce((SELECT last_analyze::text FROM pg_stat_user_tables WHERE relname = 'cloud_posture_findings'), 'never') || ' ' || coalesce((SELECT last_autoanalyze::text FROM pg_stat_user_tables WHERE relname = 'cloud_posture_findings'), 'never')"
psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" <<'SQL'
SET enable_seqscan = off;
SET enable_bitmapscan = off;
PREPARE other_count(text, text) AS SELECT count(*) FROM cloud_posture_findings f WHERE f.tenant = $1 AND f.account <> $2;
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF) EXECUTE other_count('f', 'accB');
PREPARE own_delete(text, text) AS DELETE FROM cloud_posture_findings f WHERE f.tenant = $1 AND f.account = $2;
BEGIN;
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF) EXECUTE own_delete('f', 'accA');
ROLLBACK;
PREPARE run_count(text, text) AS SELECT count(*) FROM cloud_posture_runs r WHERE r.tenant = $1 AND r.account <> $2;
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF) EXECUTE run_count('f', 'accB');
SQL

echo "--- regexes against edge inputs (expected 1 accept, 0 refuse)"
match() { sql "SELECT (\$q\$$2\$q\$ ~ \$q\$$3\$q\$)::int"; }
check "reference plain" 1 "$(match x 'arn:aws:s3:::bucket/a-b' "$REFERENCE")"
check "reference leading dash" 0 "$(match x '-a' "$REFERENCE")"
check "reference fullwidth A" 0 "$(match x 'Ａ' "$REFERENCE")"
check "reference hangul filler U+3164" 0 "$(match x 'aㅤb' "$REFERENCE")"
check "reference ESC" 0 "$(match x $'a\x1bb' "$REFERENCE")"
check "reference trailing newline" 0 "$(match x $'abc\n' "$REFERENCE")"
check "reference space" 0 "$(match x 'a b' "$REFERENCE")"
check "spaced inner space" 1 "$(match x 'Conditional Access Policy' "$SPACED")"
check "spaced word with leading dash" 0 "$(match x 'a -b' "$SPACED")"
check "spaced double space" 0 "$(match x 'a  b' "$SPACED")"
check "spaced trailing space" 0 "$(match x 'a ' "$SPACED")"
check "spaced trailing newline" 0 "$(match x $'a b\n' "$SPACED")"
check "provider plain" 1 "$(match x 'aws_2' "$PROVIDER")"
check "provider upper" 0 "$(match x 'Aws' "$PROVIDER")"
check "provider trailing newline" 0 "$(match x $'aws\n' "$PROVIDER")"
check "server encoding" UTF8 "$(sql "SHOW server_encoding")"
check "byte cap: a 128 byte check id is stored by the table, 129 refused" "ok|refused" "$(
    sql "INSERT INTO cloud_posture_findings VALUES ('z','a',decode(repeat('00',32),'hex'),5,'u','$(printf 'c%.0s' $(seq 1 128))','FAIL','High','aws','r','x','t',0,'','0','','0','run')" >/dev/null && printf ok
    printf '|'
    sql "INSERT INTO cloud_posture_findings VALUES ('z','a',decode(repeat('01',32),'hex'),5,'u','$(printf 'c%.0s' $(seq 1 129))','FAIL','High','aws','r','x','t',0,'','0','','0','run')" >/dev/null 2>&1 && printf ok || printf refused
)"
echo "failures=$failures"
exit "$failures"
REMOTE
