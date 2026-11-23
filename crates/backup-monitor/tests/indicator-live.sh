#!/usr/bin/env bash
# Usage: crates/backup-monitor/tests/indicator-live.sh <lab-state-dir>
# Live check of the restore-test indicator on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): psql and the examples run on the client VM over
# TLS against a scratch database of the datastore VM that holds migrations backup_0001 and backup_0002. Rows are written by SQL relative to the database clock, the indicator
# comes from the backup_indicators example and control 11 of builtin:cis-v8 from grc_evaluate. Every line is a check; the script exits with the failure count.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: indicator-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
target="$here/target/x86_64-unknown-linux-musl/release/examples"
for name in backup_indicators grc_evaluate; do
    [[ -x "$target/$name" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p backup-monitor --example backup_indicators -p grc --example grc_evaluate" >&2; exit 2; }
done

suffix="$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
database="backup_ind_$suffix"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists '"$database"'" || true' EXIT

for name in backup_indicators grc_evaluate; do scp "${ssh_options[@]}" "$target/$name" "$client_user@$client_address:/tmp/$name"; done
scp "${ssh_options[@]}" "$here/crates/backup-monitor/migrations/backup_0001.sql" "$here/crates/backup-monitor/migrations/backup_0002.sql" "$client_user@$client_address:/tmp/"
ssh "${ssh_options[@]}" "$client_user@$client_address" "DB=$database bash -s" <<'REMOTE'
set -euo pipefail
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf '%s' "$POSTGRES_PASSWORD" >"$work/password"
chmod 600 "$work/password"
export PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full PGSSLROOTCERT=/etc/ostyr-lab/ca.pem
P() { psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DB" "$@"; }
failures=0
check() { if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi; }
contains() { if [[ "$3" == *"$2"* ]]; then echo "PASS $1: found $2"; else echo "FAIL $1: expected [$2] in [$3]"; failures=$((failures + 1)); fi; }
P -f /tmp/backup_0001.sql >/dev/null
P -f /tmp/backup_0002.sql >/dev/null
cat >"$work/pg.yaml" <<YAML
host: $DATASTORE_DOMAIN
port: $POSTGRES_PORT
database: $DB
user: $POSTGRES_USER
password_file: $work/password
ca_file: /etc/ostyr-lab/ca.pem
YAML
printf 'evidence: []\n' >"$work/manual.yaml"

C1="$(printf 'a%.0s' $(seq 64))"
C2="$(printf 'b%.0s' $(seq 64))"
SNAP="$(printf '1%.0s' $(seq 64))"
CANARY='/d/.ostyr-restore-canary'
DIGEST="$(printf 'c%.0s' $(seq 64))"
MICROS_DAY=86400000000
NOWSQL='(extract(epoch from clock_timestamp()) * 1000000)::bigint'

declare_file() {
    local tenant="$1" critical="$2" repositories="$3" file="$work/$1.yaml"
    { echo "tenant: $tenant"
      if [[ -n "$critical" ]]; then echo "critical:"; for host in $critical; do printf '  - host: %s\n    max_age_hours: 24\n' "$host"; done; fi
      if [[ -n "$repositories" ]]; then echo "repositories:"; for repository in $repositories; do
          printf '  - repository: %s\n    expected_min_snapshots: 1\n    restore_test:\n      host: h\n      path: %s\n      sha256: %s\n      max_bytes: 10\n' "$repository" "$CANARY" "$DIGEST"
      done; fi; } >"$file"
}
row() {
    P -c "INSERT INTO backup_restore_tests (tenant, repository, host, path, config_id, category, snapshot_id, snapshot_micros, tested_micros, outcome, restored_config_id, restored_snapshot_micros, restored_tested_micros) VALUES ('$1', '$2', 'h', '$CANARY', $3, $4, $5, $6, $7, '$8', $9, ${10}, ${11})"
}
ago_days() { echo "($NOWSQL - ($1 * $MICROS_DAY)::bigint)"; }
indicator() { /tmp/backup_indicators "$work/pg.yaml" "$work/$1.yaml" "${2:-$1}" ${3:+"$3"}; }
field() { echo "$2" | jq -r ".[0].$1"; }
control() {
    echo "$2" >"$work/$1.json"
    /tmp/grc_evaluate builtin:cis-v8 "$work/$1.json" "$work/manual.yaml" "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --format json --out "$work/$1.report.json" >/dev/null || true
    jq -r '[.. | objects | select(.control? == "11" or .control? == 11 or .id? == "11" or .id? == 11)][0] | (.status // .result // .state // "unknown")' "$work/$1.report.json" 2>/dev/null || echo "unreadable"
}
ago_hours() { echo "($NOWSQL - ($1 * 3600000000)::bigint)"; }
same() { awk -v a="$1" -v b="$2" 'BEGIN { print (a + 0 == b + 0) ? "yes" : "no" }'; }
within() { awk -v v="$1" -v lo="$2" -v hi="$3" 'BEGIN { print (v >= lo && v <= hi) ? "yes" : "no" }'; }

declare_file empty "" ""
check "no test and no critical host" "[]" "$(indicator empty)"

declare_file untested "web1" ""
out="$(indicator untested)"; echo "$out"
check "critical host without a test: worst" "yes" "$(same "$(field value "$out")" 3650)"
contains "untested=1" "untested=1" "$(field source "$out")"
check "untested host: observed now" "$(date -u +%Y-%m-%d)" "$(field observed_at "$out" | cut -dT -f1)"

declare_file never "" "r1"
out="$(indicator never)"; echo "$out"
check "declared test never run: worst" "yes" "$(same "$(field value "$out")" 3650)"
contains "never=1" "never=1" "$(field source "$out")"

declare_file fresh "" "r1"
row fresh r1 "'$C1'" null "'$SNAP'" "$(ago_days 10)" "$(ago_hours 1)" timeout "'$C1'" "$(ago_days 10)" "$(ago_days 10)"
out="$(indicator fresh)"; echo "$out"
check "ten days old" "yes" "$(within "$(field value "$out")" 9.99 10.01)"
contains "restored=1" "restored=1;never=0;untested=0" "$(field source "$out")"
check "control 11 compliant" "compliant" "$(control fresh "$out")"

declare_file partial "" "r1"
row partial r1 "'$C1'" null "'$SNAP'" "$(ago_days 90.9)" "$(ago_hours 1)" timeout "'$C1'" "$(ago_days 90.9)" "$(ago_days 90.9)"
out="$(indicator partial)"; echo "$out"
check "90.9 days is 90.9, not 90" "yes" "$(within "$(field value "$out")" 90.89 90.91)"
check "control 11 partial at 90.9 days" "partially compliant" "$(control partial "$out")"

declare_file snap_old "" "r1"
row snap_old r1 "'$C1'" null "'$SNAP'" "$(ago_days 200)" "$(ago_days 1)" restored "'$C1'" "$(ago_days 200)" "$(ago_days 1)"
out="$(indicator snap_old)"
check "the snapshot time sets the age, not the test time" "yes" "$(within "$(field value "$out")" 199.99 200.01)"

declare_file replaced "" "r1"
row replaced r1 "'$C2'" null null null "$(ago_days 1)" failed "'$C1'" "$(ago_days 5)" "$(ago_days 5)"
out="$(indicator replaced)"; echo "$out"
check "restored config differs from the latest: worst" "yes" "$(same "$(field value "$out")" 3650)"
contains "config_changed=1" "config_changed=1" "$(field source "$out")"

declare_file mismatch "" "r1"
row mismatch r1 "'$C1'" null "'$SNAP'" "$(ago_days 5)" "$(ago_days 1)" digest_mismatch "'$C1'" "$(ago_days 5)" "$(ago_days 5)"
out="$(indicator mismatch)"; echo "$out"
check "latest digest mismatch after an old pass: worst" "yes" "$(same "$(field value "$out")" 3650)"

declare_file runerror "" "r1"
row runerror r1 null "'config'" null null "$(ago_days 0)" run_error "'$C1'" "$(ago_days 1)" "$(ago_days 1)"
out="$(indicator runerror)"; echo "$out"
check "restored yesterday then run_error today: worst, not 1 day" "yes" "$(same "$(field value "$out")" 3650)"

declare_file timeout "" "r1"
row timeout r1 "'$C1'" null "'$SNAP'" "$(ago_days 20)" "$(ago_days 1)" timeout "'$C1'" "$(ago_days 20)" "$(ago_days 20)"
out="$(indicator timeout)"; echo "$out"
check "latest timeout: age runs from the pass" "yes" "$(within "$(field value "$out")" 19.99 20.01)"
contains "failed_latest=1" "failed_latest=1" "$(field source "$out")"

declare_file gap "" "r1"
row gap r1 "'$C1'" null "'$SNAP'" "$(ago_days 3)" "$(ago_days 1)" listing_gap "'$C1'" "$(ago_days 3)" "$(ago_days 3)"
out="$(indicator gap)"; echo "$out"
check "latest listing_gap after a pass: worst" "yes" "$(same "$(field value "$out")" 3650)"
contains "failing=1" "failing=1" "$(field source "$out")"

declare_file future "" "r1"
row future r1 "'$C1'" null "'$SNAP'" "$(ago_days -1)" "$(ago_days -1)" restored "'$C1'" "$(ago_days -1)" "$(ago_days -1)"
out="$(indicator future)"; echo "$out"
check "a stored time a day ahead: worst" "yes" "$(same "$(field value "$out")" 3650)"
contains "future=1" "future=1" "$(field source "$out")"

declare_file twotests "" "r1 r2"
row twotests r1 "'$C1'" null "'$SNAP'" "$(ago_days 3)" "$(ago_days 3)" restored "'$C1'" "$(ago_days 3)" "$(ago_days 3)"
row twotests r2 "'$C1'" null "'$SNAP'" "$(ago_days 8)" "$(ago_days 8)" restored "'$C1'" "$(ago_days 8)" "$(ago_days 8)"
out="$(indicator twotests)"
check "the figure is the maximum over the tests" "yes" "$(within "$(field value "$out")" 7.99 8.01)"
check "observed_at is the oldest result" "$(date -u -d '8 days ago' +%Y-%m-%d)" "$(field observed_at "$out" | cut -dT -f1)"

declare_file onerow "" "r1 r2"
row onerow r1 "'$C1'" null "'$SNAP'" "$(ago_days 3)" "$(ago_days 3)" restored "'$C1'" "$(ago_days 3)" "$(ago_days 3)"
out="$(indicator onerow)"
check "one test without a row: worst" "yes" "$(same "$(field value "$out")" 3650)"
check "a member without a row: observed now" "$(date -u +%Y-%m-%d)" "$(field observed_at "$out" | cut -dT -f1)"

declare_file isolated "" "r1"
check "another tenant's row for the same key does not count" "yes" "$(same "$(field value "$(indicator isolated)")" 3650)"

declare_file mixed "web1 vm/100" "r1"
row mixed r1 "'$C1'" null "'$SNAP'" "$(ago_days 2)" "$(ago_days 2)" restored "'$C1'" "$(ago_days 2)" "$(ago_days 2)"
out="$(indicator mixed)"; echo "$out"
check "a PBS key and an untested host count" "yes" "$(same "$(field value "$out")" 3650)"
contains "untested=2" "untested=2" "$(field source "$out")"

fixed="$(date +%s)"
declare_file skew "" "r1"
row skew r1 "'$C1'" null "'$SNAP'" "$(ago_days 2)" "$(ago_days 2)" restored "'$C1'" "$(ago_days 2)" "$(ago_days 2)"
refused="$(indicator skew skew "$((fixed + 47 * 3600))" 2>&1 || true)"
contains "47 h off the database clock is refused" "ClockSkew" "$refused"
accepted="$(indicator skew skew "$((fixed + 60))" 2>&1 || true)"
contains "a minute off is accepted" '"value"' "$accepted"

declare_file ahead "" "r1 r2"
row ahead r1 "'$C1'" null "'$SNAP'" "$(ago_days 3)" "$(ago_days 3)" restored "'$C1'" "$(ago_days 3)" "$(ago_days 3)"
out="$(indicator ahead ahead "$(($(date +%s) + 250))")"; echo "$out"
seen_at="$(date -u -d "$(field observed_at "$out")" +%s)"
check "a caller 250 s ahead gives no future observed_at" "yes" "$([[ "$seen_at" -le "$(date +%s)" ]] && echo yes || echo no)"

wrong="$(indicator skew other 2>&1 || true)"
contains "a tenant argument different from the declarations is refused" "DeclarationsTenant" "$wrong"

fixed="$(date +%s)"
declare_file digits "" "r1"
row digits r1 "'$C1'" null "'$SNAP'" "$(ago_days 90.9)" "$(ago_hours 1)" timeout "'$C1'" "$(ago_days 90.9)" "$(ago_days 90.9)"
first=''
for digits in -15 0 3; do
    P -c "ALTER DATABASE $DB SET extra_float_digits = $digits" >/dev/null
    current="$(indicator digits digits "$fixed")"
    echo "extra_float_digits $digits: $current"
    if [[ -z "$first" ]]; then first="$current"; fi
    check "extra_float_digits $digits gives the same bytes" "$first" "$current"
done
echo "failures: $failures"
exit "$failures"
REMOTE
