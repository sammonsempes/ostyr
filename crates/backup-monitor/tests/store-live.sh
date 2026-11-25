#!/usr/bin/env bash
# Usage: crates/backup-monitor/tests/store-live.sh <lab-state-dir>   (env: MUTANT=<name> mutates migrations/backup_0002.sql, see the case list below)
# Live check of the restore-test store on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): psql runs on the client VM over TLS against two
# scratch databases of the datastore VM. Database one holds the migration applied by psql: the function scenarios (two tenants with one key, the cap, the
# newest result per key, the clamps, run errors, the CHECKs, a plan under stale statistics). Database two is migrated and written by the real ostyr-backup-monitor
# service with a fake restic script (a run, then a run whose `cat config` fails). Every line is a check; a mutant must make at least one fail.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: store-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
binary="$here/target/x86_64-unknown-linux-musl/release/ostyr-backup-monitor"
[[ -x "$binary" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p backup-monitor --bin ostyr-backup-monitor" >&2; exit 2; }

suffix="$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
for database in "backup_live_f_$suffix" "backup_live_x_$suffix"; do datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"; done
trap 'for database in backup_live_f_'"$suffix"' backup_live_x_'"$suffix"'; do datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true; done' EXIT

scp "${ssh_options[@]}" "$binary" "$client_user@$client_address:/tmp/ostyr-backup-monitor"
scp "${ssh_options[@]}" "$here/crates/backup-monitor/migrations/backup_0001.sql" "$here/crates/backup-monitor/migrations/backup_0002.sql" \
    "$here/crates/backup-monitor/tests/fixtures/fake-restic-dump.sh" \
    "$client_user@$client_address:/tmp/"
ssh "${ssh_options[@]}" "$client_user@$client_address" "SUFFIX=$suffix MUTANT=${MUTANT:-} bash -s" <<'REMOTE'
set -euo pipefail
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf '%s' "$POSTGRES_PASSWORD" >"$work/password"
chmod 600 "$work/password"
export PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full PGSSLROOTCERT=/etc/ostyr-lab/ca.pem
FDB="backup_live_f_$SUFFIX"
XDB="backup_live_x_$SUFFIX"
P() { psql -X -q -tA -v ON_ERROR_STOP=0 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$FDB" "$@"; }
S() { P -v ON_ERROR_STOP=1 -c "$1"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
contains() {
    if [[ "$3" == *"$2"* ]]; then echo "PASS $1: found $2"; else echo "FAIL $1: expected [$2] in [$3]"; failures=$((failures + 1)); fi
}

migration="$work/backup_0002.sql"
cp /tmp/backup_0002.sql "$migration"
case "${MUTANT:-}" in
    "") ;;
    no-clock) sed -i 's/WHERE r.tested_micros > now_micros + skew \* 1000000/WHERE false/' "$migration" ;;
    overwrite-older) sed -i 's/WHERE st.tested_micros < EXCLUDED.tested_micros/WHERE true/; s/WHERE j.old_tested IS NULL OR j.old_tested < j.tested_micros/WHERE true/' "$migration" ;;
    keep-restored) sed -i 's/WHEN st.restored_config_id IS DISTINCT FROM EXCLUDED.config_id THEN NULL/WHEN false THEN NULL/' "$migration" ;;
    no-prune) sed -i 's/WHERE t.tenant = p_tenant AND NOT EXISTS (/WHERE false AND NOT EXISTS (/' "$migration" ;;
    tenant-joined) sed -i 's/ON s.tenant = p_tenant AND s.repository = i.repository/ON s.repository = i.repository/' "$migration" ;;
    tenant-cap) sed -i 's/WHERE t.tenant = p_tenant AND t.repository = d.repository/WHERE t.repository = d.repository/' "$migration" ;;
    distinct-oldest) sed -i 's/r.tested_micros DESC/r.tested_micros/' "$migration" ;;
    no-clamp-cap) sed -i 's/least(greatest(p_cap, 0), 10000)/p_cap/' "$migration" ;;
    no-clamp-skew) sed -i 's/least(greatest(p_max_skew_seconds, 0), 300)/p_max_skew_seconds/' "$migration" ;;
    skip-db-clock) sed -i "s/CASE WHEN e.db_clock IS TRUE THEN now_micros ELSE e.tested_micros END AS tested_micros/e.tested_micros/" "$migration" ;;
    tie-restored-first) sed -i "s/(r.outcome = 'restored') ASC/(r.outcome = 'restored') DESC/" "$migration" ;;
    tie-restored) sed -i "s/, (r.outcome = 'restored') ASC, (r.outcome = 'run_error') DESC//" "$migration" ;;
    run-error-clears) sed -i "s/WHEN EXCLUDED.outcome = 'run_error' THEN st.restored_/WHEN false THEN st.restored_/" "$migration" ;;
    *) echo "unknown mutant ${MUTANT}"; exit 2 ;;
esac
if [[ -n "${MUTANT:-}" ]]; then echo "MUTANT ${MUTANT}"; diff /tmp/backup_0002.sql "$migration" || true; fi

P -v ON_ERROR_STOP=1 -f /tmp/backup_0001.sql >/dev/null
P -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
S "ALTER TABLE backup_restore_tests SET (autovacuum_enabled = false)" >/dev/null

C1="$(printf 'a%.0s' $(seq 64))"
C2="$(printf 'b%.0s' $(seq 64))"
SNAP="$(printf '1%.0s' $(seq 64))"
CANARY='/d/.ostyr-restore-canary'
ent() { printf '{"repository":"%s","host":"h","path":"%s","config_id":%s,"snapshot_id":%s,"snapshot_micros":%s,"tested_micros":%s,"outcome":"%s","category":%s}' \
    "$1" "$CANARY" "$2" "$3" "$4" "$5" "$6" "$7"; }
restored() { ent "$1" "\"$C1\"" "\"$SNAP\"" "$3" "$2" restored null; }
declared() { local sep=''; for name in "$@"; do printf '%s{"repository":"%s","host":"h","path":"%s"}' "$sep" "$name" "$CANARY"; sep=','; done; }
call() { S "SELECT outcome||'|'||written||'|'||stale_write||'|'||config_changed||'|'||pruned||'|'||row_count FROM public.backup_restore_record('$1', '[$2]'::jsonb, '[$3]'::jsonb, $4, $5)"; }
cell() { S "SELECT $2 FROM backup_restore_tests WHERE tenant = '$1' AND repository = '$3'"; }

check "t1 first write" "ok|1|0|0|0|1" "$(call t1 "$(restored r1 2000000 1900000)" "$(declared r1)" 10000 300)"
check "t1 replayed older result" "ok|0|1|0|0|1" "$(call t1 "$(restored r1 1000000 900000)" "$(declared r1)" 10000 300)"
check "t1 stored time unchanged" "2000000" "$(cell t1 tested_micros r1)"
check "t1 run error stored" "ok|1|0|0|0|1" "$(call t1 "$(ent r1 null null null 3000000 run_error '"config"')" "$(declared r1)" 10000 300)"
check "t1 run error keeps the last pass" "run_error|config|$C1|2000000" "$(cell t1 "outcome||'|'||category||'|'||restored_config_id||'|'||restored_tested_micros" r1)"
check "t1 replaced repository" "ok|1|0|1|0|1" "$(call t1 "$(ent r1 "\"$C2\"" null null 4000000 no_snapshot null)" "$(declared r1)" 10000 300)"
check "t1 restored columns cleared" "-" "$(cell t1 "coalesce(restored_config_id, '-')" r1)"
check "t1 prune" "ok|0|0|0|1|0" "$(call t1 '' '' 10000 300)"
check "t1 table empty" "0" "$(S "SELECT count(*) FROM backup_restore_tests WHERE tenant = 't1'")"

check "tenant A first" "ok|1|0|0|0|1" "$(call ta "$(restored k 1000000 900000)" "$(declared k)" 10000 300)"
check "tenant B later time" "ok|1|0|0|0|1" "$(call tb "$(restored k 5000000 4900000)" "$(declared k)" 10000 300)"
check "tenant A is not stale against tenant B" "ok|1|0|0|0|1" "$(call ta "$(restored k 2000000 1900000)" "$(declared k)" 10000 300)"
check "tenant A time" "2000000" "$(cell ta tested_micros k)"
check "tenant B time" "5000000" "$(cell tb tested_micros k)"

check "tenant B holds three rows" "ok|3|0|0|0|3" "$(call tb2 "$(restored k1 1000000 900000),$(restored k2 1000000 900000),$(restored k3 1000000 900000)" "$(declared k1 k2 k3)" 10000 300)"
check "tenant B rows do not count toward tenant A" "ok|2|0|0|0|2" \
    "$(call tc2 "$(restored k1 1000000 900000),$(restored k2 1000000 900000)" "$(declared k1 k2 k3)" 2 300)"
check "tenant A at the cap" "row_cap|0|0|0|0|3" \
    "$(call tc2 "$(restored k1 1500000 900000),$(restored k2 1500000 900000),$(restored k3 1500000 900000)" "$(declared k1 k2 k3)" 2 300)"
check "cap refusal wrote nothing" "2|1000000" "$(S "SELECT count(*)||'|'||max(tested_micros) FROM backup_restore_tests WHERE tenant = 'tc2'")"

dbclock() { printf '{"repository":"%s","host":"h","path":"%s","config_id":null,"snapshot_id":null,"snapshot_micros":null,"tested_micros":null,"db_clock":%s,"outcome":"%s","category":%s}' \
    "$1" "$CANARY" "$2" "$3" "$4"; }
check "unstorable time stored as run error" "ok|1|0|0|0|1" "$(call tj "$(dbclock k true run_error '"invalid"')" "$(declared k)" 10000 300)"
check "unstorable time row stamped with the database clock" "run_error|invalid|1" \
    "$(cell tj "outcome||'|'||category||'|'||(abs(tested_micros - (extract(epoch from clock_timestamp())*1000000)::bigint) < 60000000)::int" k)"
check "null time without db_clock is refused" "bad_time|0|0|0|0|0" "$(call tk "$(dbclock k false run_error '"invalid"')" "$(declared k)" 10000 300)"
check "db_clock on a restored entry is refused" "bad_time|0|0|0|0|0" "$(call tk "$(dbclock k true restored null)" "$(declared k)" 10000 300)"
check "bad time wrote nothing" "0" "$(S "SELECT count(*) FROM backup_restore_tests WHERE tenant = 'tk'")"
check "a tie is won by the run error" "ok|1|0|0|0|1" "$(call tl "$(restored k 2000000 1900000),$(ent k null null null 2000000 run_error '"failed"')" "$(declared k)" 10000 300)"
check "tie winner stored" "run_error" "$(cell tl outcome k)"
check "a tie is won by the run error in the other order" "ok|1|0|0|0|1" "$(call tm "$(ent k null null null 2000000 run_error '"failed"'),$(restored k 2000000 1900000)" "$(declared k)" 10000 300)"
check "tie winner stored in the other order" "run_error" "$(cell tm outcome k)"

check "a tie is won by any failure over a restored" "ok|1|0|0|0|1" "$(call tn "$(restored k 2000000 1900000),$(ent k "\"$C1\"" null null 2000000 no_snapshot null)" "$(declared k)" 10000 300)"
check "tie winner over a restored stored" "no_snapshot" "$(cell tn outcome k)"

check "newest result per key" "ok|1|0|0|0|1" "$(call td "$(restored k 2000000 1900000),$(restored k 3000000 2900000)" "$(declared k)" 10000 300)"
check "newest result kept" "3000000" "$(cell td tested_micros k)"

entries_sql="jsonb_build_object('repository','r'||g,'host','h','path','$CANARY','config_id','$C1','snapshot_id',null,'snapshot_micros',null,'tested_micros',1000000,'outcome','no_snapshot','category',null)"
declared_sql="jsonb_build_object('repository','r'||g,'host','h','path','$CANARY')"
check "cap clamped inside the function" "row_cap|10001" \
    "$(S "SELECT outcome||'|'||row_count FROM public.backup_restore_record('te', (SELECT jsonb_agg($entries_sql) FROM generate_series(1,10001) g), (SELECT jsonb_agg($declared_sql) FROM generate_series(1,10001) g), 1000000, 300)")"
check "nothing written over the clamped cap" "0" "$(S "SELECT count(*) FROM backup_restore_tests WHERE tenant = 'te'")"
ahead() { S "SELECT outcome||'|'||written FROM public.backup_restore_record('$1', jsonb_build_array(jsonb_build_object('repository','r','host','h','path','$CANARY','config_id','$C1','snapshot_id',null,'snapshot_micros',null,'tested_micros',(extract(epoch from clock_timestamp())*1000000)::bigint + $2,'outcome','no_snapshot','category',null)), '[$3]'::jsonb, 10000, $4)"; }
check "skew clamped inside the function" "clock_skew|0" "$(ahead tf 86400000000 "$(declared r)" 86400)"
check "a runner clock one year ahead" "clock_skew|0" "$(ahead tf 31536000000000 "$(declared r)" 300)"
check "nothing written by a skewed run" "0" "$(S "SELECT count(*) FROM backup_restore_tests WHERE tenant = 'tf'")"
check "an honest result is written after" "ok|1" "$(ahead tf 0 "$(declared r)" 300)"

refusal() {
    contains "$1" "$2" "$(P -c "INSERT INTO backup_restore_tests (tenant, repository, host, path, config_id, snapshot_id, snapshot_micros, tested_micros, outcome, category, restored_config_id, restored_snapshot_micros, restored_tested_micros) VALUES ('tx', 'r', 'h', '$CANARY', $3)" 2>&1)"
}
refusal "hand insert restored without snapshot" backup_restore_tests_restored_snapshot "'$C1', null, null, 1, 'restored', null, null, null, null"
refusal "hand insert run error with a config id" backup_restore_tests_category "'$C1', null, null, 1, 'run_error', 'failed', null, null, null"
refusal "hand insert a result without a config id" backup_restore_tests_ids "null, null, null, 1, 'failed', null, null, null, null"
refusal "hand insert an unknown category" backup_restore_tests_category "null, null, null, 1, 'run_error', 'bogus', null, null, null"
refusal "hand insert half restored columns" backup_restore_tests_restored_all_or_none "'$C1', null, null, 1, 'failed', null, '$C1', null, null"

S "INSERT INTO backup_restore_tests (tenant, repository, host, path, config_id, tested_micros, outcome) SELECT 'tg', 'r'||g, 'h', '$CANARY', '$C1', 1, 'no_snapshot' FROM generate_series(1,9000) g" >/dev/null
check "9000 unanalysed rows of a new tenant" "ok|9000|0|0|0|9000" "$(P -v ON_ERROR_STOP=1 -c "SET statement_timeout = '20s'" -c "SELECT outcome||'|'||written||'|'||stale_write||'|'||config_changed||'|'||pruned||'|'||row_count FROM public.backup_restore_record('tg', (SELECT jsonb_agg(jsonb_build_object('repository','r'||g,'host','h','path','$CANARY','config_id','$C1','snapshot_id',null,'snapshot_micros',null,'tested_micros',2,'outcome','no_snapshot','category',null)) FROM generate_series(1,9000) g), (SELECT jsonb_agg($declared_sql) FROM generate_series(1,9000) g), 10000, 300)" | tail -1)"
S "INSERT INTO backup_restore_tests (tenant, repository, host, path, config_id, tested_micros, outcome) SELECT 'th', 'r'||g, 'h', '$CANARY', '$C1', 1, 'no_snapshot' FROM generate_series(1,9000) g" >/dev/null
plan="$(P <<SQL
SELECT jsonb_agg(jsonb_build_object('repository','r'||g,'host','h','path','$CANARY')) AS j FROM generate_series(1,9000) g \gset
PREPARE q(text, jsonb) AS SELECT count(s.tenant) FROM jsonb_to_recordset(\$2) AS i(repository text, host text, path text) LEFT JOIN backup_restore_tests s ON s.tenant = \$1 AND s.repository = i.repository AND s.host = i.host AND s.path = i.path;
EXPLAIN ANALYZE EXECUTE q('th', :'j');
SQL
)"
echo "$plan" | head -20
contains "plan under stale statistics" "Execution Time" "$plan"

cat >"$work/pg.yaml" <<YAML
host: $DATASTORE_DOMAIN
port: $POSTGRES_PORT
database: $XDB
user: $POSTGRES_USER
password_file: $work/password
ca_file: /etc/ostyr-lab/ca.pem
YAML
fake="$work/fake"
mkdir "$fake"
install -m 755 /tmp/fake-restic-dump.sh "$fake/restic"
printf 'ok' >"$fake/mode"
printf 'canary bytes\n' >"$fake/canary"
printf '{"version":2,"id":"%s"}' "$C1" >"$fake/config.json"
snapshot_id="$(printf '2%.0s' $(seq 64))"
printf '[{"time":"%s","paths":["/data"],"hostname":"web1","id":"%s","short_id":"x"}]' "$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" "$snapshot_id" >"$fake/snapshots.json"
printf '%s\n' "$snapshot_id" >"$fake/list.txt"
printf 'hunter2\n' >"$fake/password"
chmod 600 "$fake/password"
chmod 700 "$fake"
digest="$(sha256sum "$fake/canary" | cut -d' ' -f1)"
{
    echo "tenant: live2"
    echo "repositories:"
    for name in main second; do
        printf '  - repository: %s\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/%s\n      password_file: password\n' "$name" "$name"
        printf '    restore_test:\n      host: web1\n      path: /data/.ostyr-restore-canary\n      sha256: %s\n      max_bytes: 100\n' "$digest"
    done
} >"$work/declarations.yaml"
mkdir -m 700 "$work/state"
cat >"$work/service.yaml" <<YAML
tenant: live2
declarations_file: $work/declarations.yaml
state_dir: $work/state
secrets_dir: $fake
pg_settings: $work/pg.yaml
audit_file: $work/audit.log
interval_seconds: 3600
restore_interval_seconds: 3600
YAML
printf '#!/bin/sh\nexec %s/restic "$@"\n' "$fake" >"$work/restic-wrapper"
if [[ -e /usr/bin/restic ]]; then sudo mv /usr/bin/restic /usr/bin/restic.real; fi
trap 'sudo rm -f /usr/bin/restic; if [[ -e /usr/bin/restic.real ]]; then sudo mv /usr/bin/restic.real /usr/bin/restic; fi; rm -rf "$work"' EXIT
sudo install -m 755 "$work/restic-wrapper" /usr/bin/restic
X() { psql -X -q -tA -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$XDB" -c "$1"; }
service_round() {
    rm -f "$work/audit.log"
    timeout 120 /tmp/ostyr-backup-monitor "$work/service.yaml" 2>"$work/service.err" &
    local pid=$!
    for _ in $(seq 300); do
        [[ "$(grep -c . "$work/audit.log" 2>/dev/null || true)" -ge 2 ]] && break
        sleep 0.2
    done
    kill -INT "$pid"
    local status=0
    wait "$pid" || status=$?
    check "service exits 0 on SIGINT" "0" "$status" >&2
    python3 -I -c 'import json,sys
for line in open(sys.argv[1]):
    record = json.loads(line)
    if record["action"] == "backup.restore_round":
        keys = ["written", "stale_write", "config_changed", "pruned", "skipped_invalid", "run_error"]
        print(json.dumps({"store": {key: int(record["parameters"][key]) for key in keys}}, sort_keys=True, separators=(",", ":")))' "$work/audit.log"
}
first="$(service_round)"
echo "$first"
check "service first run stores both tests" '{"store":{"config_changed":0,"pruned":0,"run_error":0,"skipped_invalid":0,"stale_write":0,"written":2}}' "$first"
check "service rows restored" "2" "$(X "SELECT count(*) FROM backup_restore_tests WHERE outcome = 'restored' AND restored_config_id IS NOT NULL")"
touch "$fake/config.fail"
second="$(service_round)"
echo "$second"
check "service config failure stores a run error per test" '{"store":{"config_changed":0,"pruned":0,"run_error":2,"skipped_invalid":0,"stale_write":0,"written":2}}' "$second"
check "service rows are run errors that keep the last pass" "2" \
    "$(X "SELECT count(*) FROM backup_restore_tests WHERE outcome = 'run_error' AND category = 'failed' AND config_id IS NULL AND restored_config_id = '$C1' AND restored_tested_micros IS NOT NULL")"
echo "failures: $failures"
exit "$failures"
REMOTE
