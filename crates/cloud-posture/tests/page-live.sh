#!/usr/bin/env bash
# Usage: bash crates/cloud-posture/tests/page-live.sh <lab-state-dir>
# Live check of the posture paged read (T699B) on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the posture_store example, built for musl
# (cargo build --release --target x86_64-unknown-linux-musl -p cloud-posture --example posture_store), runs on the client VM against a scratch database:
# walks by cursor, tenant isolation, a cursor reused after a replace, the refusal marker of a run too large, EXPLAIN ANALYZE of the page statement under
# stale statistics, and hostile rows inserted by psql with the CHECKs dropped.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: page-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
binary="$here/target/x86_64-unknown-linux-musl/release/examples/posture_store"
[[ -x "$binary" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p cloud-posture --example posture_store" >&2; exit 2; }

database="posture_page_$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true' EXIT

scp "${ssh_options[@]}" "$binary" "$client_user@$client_address:/tmp/posture_store"
ssh "${ssh_options[@]}" "$client_user@$client_address" "DATABASE=$database bash -s" <<'REMOTE'
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
next_of() { sed -n 's/^unservable=[0-9]* next=Some("\(.*\)") rows=.*/\1/p'; }

posture migrate
posture migrate
check "migrations recorded" "2" "$(sql "SELECT count(*) FROM schema_migrations WHERE namespace = 'posture'")"
check "marker function exists" "1" "$(sql "SELECT count(*) FROM pg_proc WHERE proname = 'posture_refuse_run'")"
sql "ALTER TABLE cloud_posture_findings SET (autovacuum_enabled = false)"
sql "ALTER TABLE cloud_posture_runs SET (autovacuum_enabled = false)"

walk() {
    local cursor="" out="" page
    WALK_UIDS=""
    WALK_PAGES=0
    for page in $(seq 1 700); do
        if [[ -z "$cursor" ]]; then out="$(posture read "$1" "$2" "$3")"; else out="$(posture read "$1" "$2" "$3" "$cursor")"; fi
        WALK_UIDS+="$(grep '^row ' <<<"$out" | awk '{print $2}' | tr -d '"' | tr '\n' ' ')"
        cursor="$(next_of <<<"$out")"
        WALK_PAGES=$page
        [[ -n "$cursor" ]] || break
    done
    WALK_UIDS="${WALK_UIDS% }"
}
ordered() { sql "SELECT coalesce(string_agg(uid, ' ' ORDER BY severity_rank DESC, identity), '') FROM cloud_posture_findings WHERE tenant = '$1' AND account = '$2'"; }

echo "--- a walk over 1000 rows by cursor"
posture bulk a acc1 run1 $NOW 1000 a1 >/dev/null
walk a acc1 100
check "1000 rows in 10 pages" "1000|10" "$(wc -w <<<"$WALK_UIDS" | tr -d ' ')|$WALK_PAGES"
check "every uid once" 1000 "$(tr ' ' '\n' <<<"$WALK_UIDS" | sort -u | wc -l | tr -d ' ')"
check "walk order is the table order (severity desc, identity)" "$(ordered a acc1)" "$WALK_UIDS"
walk a acc1 333
check "pages of 333: 4 pages, same order" "4|$(ordered a acc1)" "$WALK_PAGES|$WALK_UIDS"
posture bulk s acc1 run1 $NOW 25 s1 >/dev/null
walk s acc1 1
check "one row per page over 25 rows" "25|$(ordered s acc1)" "$WALK_PAGES|$WALK_UIDS"
check "an account with no run is an empty page" "run None refusal_pending=false
unservable=0 next=None rows=0" "$(posture read a nothing 10)"
check "a limit of 0 is refused" "error BadLimit { max: 500 }" "$(posture read a acc1 0)"
check "a limit of 501 is refused" "error BadLimit { max: 500 }" "$(posture read a acc1 501)"
check "a forged cursor is refused" "error BadCursor" "$(posture read a acc1 5 'run1 1 5 zz')"
header="$(posture read a acc1 3 | sed -n 1p)"
echo "header of a: $header"
check "header names the run and the counts" 1 "$(grep -c 'run_id: Some("run1"), finished_micros: Some(1700000000000000), items: 1000' <<<"$header")"

echo "--- tenant isolation: tenant b, the same account id, a forged cursor from a"
posture bulk b acc1 run1 $NOW 3 b1 >/dev/null
cursor_a="$(posture read a acc1 10 | next_of)"
b_rows="$(posture read b acc1 10)"
check "b reads only its 3 rows" "3|0" "$(grep -c '^row "b1-' <<<"$b_rows")|$(grep -c '^row "a1-' <<<"$b_rows")"
b_forged="$(posture read b acc1 500 "$cursor_a")"
check "a's cursor on b never shows a's rows" 0 "$(grep -c '^row "a1-' <<<"$b_forged")"
check "a's cursor on b shows only b rows" "$(grep -c '^row ' <<<"$b_forged")" "$(grep -c '^row "b1-' <<<"$b_forged")"
check "a tenant with no rows and a's cursor is RunChanged" "error RunChanged" "$(posture read c acc1 10 "$cursor_a")"
check "rows of a and b untouched" "1000|3" "$(rows a acc1)|$(rows b acc1)"

echo "--- a cursor reused after a replace"
posture bulk a acc1 run2 $((NOW + 1)) 1000 a2 >/dev/null
check "old cursor after a replace with another run id" "error RunChanged" "$(posture read a acc1 10 "$cursor_a")"
cursor_run2="$(posture read a acc1 10 | next_of)"
check "the new cursor works" 10 "$(posture read a acc1 10 "$cursor_run2" | grep -c '^row ')"
posture bulk a acc1 run2 $((NOW + 5)) 1000 a3 >/dev/null
check "same run id, new finish time" "error RunChanged" "$(posture read a acc1 10 "$cursor_run2")"

echo "--- a run too large to send writes the refusal marker"
check "oversized run on a new account" "1" "$(posture bulk m acc1 run1 $NOW 200001 mm | grep -c 'Err(RunTooLarge { items: 200001')"
check "marker row" "|200001|0" "$(sql "SELECT coalesce(run_id, '') || '|' || refused_items || '|' || items FROM cloud_posture_runs WHERE tenant = 'm' AND account = 'acc1'")"
refused_page="$(posture read m acc1 10)"
check "the page names the refusal" "1|1|0" "$(grep -c 'refused_items: 200001' <<<"$refused_page")|$(grep -c 'refusal_pending=true' <<<"$refused_page")|$(grep -c '^row ' <<<"$refused_page")"
posture bulk n acc1 run1 $NOW 3 n1 >/dev/null
posture bulk n acc1 run2 $((NOW + 7)) 200001 nn >/dev/null
kept_page="$(posture read n acc1 10)"
check "older rows kept, newer refusal named" "3|1|1" "$(rows n acc1)|$(grep -c 'refusal_pending=true' <<<"$kept_page")|$(grep -c 'run_id: Some("run1")' <<<"$kept_page")"
check "a refused run takes the marker only" "run1|3|$((NOW + 7))|200001" "$(sql "SELECT run_id || '|' || items || '|' || refused_micros || '|' || refused_items FROM cloud_posture_runs WHERE tenant = 'n'")"
posture bulk n acc1 run3 $((NOW + 9)) 2 n3 >/dev/null
check "a stored run clears the marker" "run3|2||0" "$(sql "SELECT run_id || '|' || items || '|' || coalesce(refused_micros::text, '') || '|' || refused_items FROM cloud_posture_runs WHERE tenant = 'n'")"

echo "--- plans under stale statistics (autovacuum off, no ANALYZE, a new tenant with 100000 rows)"
posture bulk f accA run1 $NOW 100000 fa >/dev/null
sql "SELECT 'analyzed: ' || coalesce((SELECT last_analyze::text FROM pg_stat_user_tables WHERE relname = 'cloud_posture_findings'), 'never') || ' ' || coalesce((SELECT last_autoanalyze::text FROM pg_stat_user_tables WHERE relname = 'cloud_posture_findings'), 'never')"
page_sql="$(posture page-sql)"
mid="$(sql "SELECT severity_rank || ' ' || encode(identity, 'hex') FROM cloud_posture_findings WHERE tenant = 'f' ORDER BY severity_rank DESC, identity OFFSET 70000 LIMIT 1")"
mid_rank="${mid% *}"
mid_identity="${mid#* }"
last="$(sql "SELECT severity_rank || ' ' || encode(identity, 'hex') FROM cloud_posture_findings WHERE tenant = 'f' ORDER BY severity_rank DESC, identity OFFSET 99998 LIMIT 1")"
last_rank="${last% *}"
last_identity="${last#* }"
plans="$work/plans.txt"
psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" >"$plans" <<SQL
PREPARE page(text, text, text, text, text) AS ${page_sql};
SELECT '== first page';
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF) EXECUTE page('f', 'accA', '8', '', '101');
SELECT '== middle page';
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF) EXECUTE page('f', 'accA', '${mid_rank}', '${mid_identity}', '101');
SELECT '== last page';
EXPLAIN (ANALYZE, TIMING OFF, SUMMARY OFF) EXECUTE page('f', 'accA', '${last_rank}', '${last_identity}', '101');
SQL
cat "$plans"
check "no sequential scan in any plan" 0 "$(grep -c 'Seq Scan' "$plans")"
check "no plan reads a whole tenant" 0 "$(grep -c 'rows=100000\|rows=[0-9]\{5,\} ' "$plans")"
check "index scans on the findings table" 1 "$([[ "$(grep -c 'Index.*cloud_posture_findings' "$plans")" -ge 3 ]] && echo 1 || echo 0)"

echo "--- hostile rows inserted by psql with the CHECKs dropped"
posture bulk h acc1 run1 $NOW 6 hg >/dev/null
sql "DO \$\$ DECLARE c record; BEGIN FOR c IN SELECT conname FROM pg_constraint WHERE conrelid = 'cloud_posture_findings'::regclass AND contype = 'c' LOOP EXECUTE format('ALTER TABLE cloud_posture_findings DROP CONSTRAINT %I', c.conname); END LOOP; END \$\$"
check "no CHECK left" 0 "$(sql "SELECT count(*) FROM pg_constraint WHERE conrelid = 'cloud_posture_findings'::regclass AND contype = 'c'")"
sql "UPDATE cloud_posture_findings SET title = repeat('t', 2000) WHERE tenant = 'h' AND uid = 'hg-0'"
sql "UPDATE cloud_posture_findings SET title = E'esc\\x1b[31mred <b>x</b>' WHERE tenant = 'h' AND uid = 'hg-1'"
sql "UPDATE cloud_posture_findings SET check_id = '<svg/onload=alert(1)>' WHERE tenant = 'h' AND uid = 'hg-2'"
sql "UPDATE cloud_posture_findings SET time_unix = 99999999999999 WHERE tenant = 'h' AND uid = 'hg-3'"
sql "UPDATE cloud_posture_findings SET severity_rank = 0 WHERE tenant = 'h' AND uid = 'hg-4'"
hostile="$(posture read h acc1 10)"
echo "$hostile" | cat -v
check "four hostile rows skipped and counted" "unservable=4 next=None rows=2" "$(grep '^unservable=' <<<"$hostile")"
check "no raw ESC byte reaches the output" 0 "$(grep -c $'\x1b' <<<"$hostile" || true)"
check "the ESC is shown escaped" 1 "$(grep -c 'esc\\\\u{1b}\[31mred' <<<"$hostile")"
check "no text of a skipped row is printed" 0 "$(grep -c 'svg\|tttttttt' <<<"$hostile" || true)"
check "the two served rows are hg-1 and hg-5" "hg-1 hg-5" "$(grep '^row ' <<<"$hostile" | awk '{print $2}' | tr -d '"' | sort | tr '\n' ' ' | sed 's/ $//')"
echo "failures=$failures"
exit "$failures"
REMOTE
