#!/usr/bin/env bash
# Usage: crates/cases/tests/store-live.sh <lab-state-dir>   (env: MUTANT=<name> mutates migrations/indicator.sql or apply.sql, BIG=0 skips the 1 M plan)
# Live check of the cases store on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): psql runs on the client VM over TLS against a scratch
# database of the datastore VM. It proves migration 004 (backfill, CHECKs), the action matrix over apply.sql (closed_at, ever_incident), the statement of the
# incident.mean_hours_to_close indicator (scenarios, tenant isolation, plan under stale statistics) and the cases_indicators example. Every line is a check.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: store-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
binary="$here/target/x86_64-unknown-linux-musl/release/examples/cases_indicators"
[[ -x "$binary" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p cases --example cases_indicators" >&2; exit 2; }

database="cases_live_$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true' EXIT

scp "${ssh_options[@]}" "$binary" "$client_user@$client_address:/tmp/cases_indicators"
ssh "${ssh_options[@]}" "$client_user@$client_address" "rm -rf /tmp/cases-sql && mkdir /tmp/cases-sql"
scp "${ssh_options[@]}" "$here"/crates/cases/migrations/*.sql "$client_user@$client_address:/tmp/cases-sql/"
ssh "${ssh_options[@]}" "$client_user@$client_address" "DATABASE=$database MUTANT=${MUTANT:-} BIG=${BIG:-1} bash -s" <<'REMOTE'
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
P() { psql -X -q -tA -v ON_ERROR_STOP=0 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" "$@"; }
S() { P -v ON_ERROR_STOP=1 -c "$1"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
D=/tmp/cases-sql
M="$work/mutant"
mkdir -p "$M"
cp "$D"/*.sql "$M"/
case "${MUTANT:-}" in
    "") ;;
    only-closed) sed -i "s/WHERE tenant = \$1 AND status <> 'closed'/WHERE tenant = \$1 AND false/" "$M/indicator.sql" ;;
    resolution) sed -i "s/SELECT status, ever_incident, created_at/SELECT status, (resolution IN ('true_positive', 'other')) AS ever_incident, created_at/" "$M/indicator.sql" ;;
    created-window) sed -i "s/(closed_at >= \$2::text::bigint - \$3::text::bigint OR created_at/(false OR created_at/" "$M/indicator.sql" ;;
    bad-row-age) sed -i "s/GREATEST(\$3::text::bigint, CASE WHEN created_at <= \$2::text::bigint THEN \$2::text::bigint - created_at ELSE 0 END)/(\$2::text::bigint - created_at)/" "$M/indicator.sql" ;;
    tenant-open) sed -i "0,/WHERE tenant = \$1 AND status <> 'closed'/s//WHERE true AND status <> 'closed'/" "$M/indicator.sql" ;;
    tenant-closed) sed -i "s/WHERE tenant = \$1 AND status = 'closed'/WHERE true AND status = 'closed'/" "$M/indicator.sql" ;;
    tenant-exists) sed -i "s/EXISTS (SELECT 1 FROM cases WHERE tenant = \$1)/EXISTS (SELECT 1 FROM cases)/" "$M/indicator.sql" ;;
    updated-at) sed -i "s/SELECT status, ever_incident, created_at, closed_at FROM cases WHERE tenant = \$1 AND status = 'closed'/SELECT status, ever_incident, created_at, updated_at AS closed_at FROM cases WHERE tenant = \$1 AND status = 'closed'/" "$M/indicator.sql"
        sed -i "s/SELECT status, ever_incident, created_at, closed_at FROM cases WHERE tenant = \$1 AND status <> 'closed'/SELECT status, ever_incident, created_at, updated_at AS closed_at FROM cases WHERE tenant = \$1 AND status <> 'closed'/" "$M/indicator.sql" ;;
    apply-flag-overwritten) sed -i "s/cases.ever_incident OR coalesce(/coalesce(/" "$M/apply.sql" ;;
    apply-closed-kept) sed -i "s/THEN change.updated_at END,/THEN change.updated_at ELSE cases.closed_at END,/" "$M/apply.sql" ;;
    *) echo "unknown mutant ${MUTANT}"; exit 2 ;;
esac
if [[ -n "${MUTANT:-}" ]]; then echo "MUTANT ${MUTANT}"; diff "$D/indicator.sql" "$M/indicator.sql" || true; diff "$D/apply.sql" "$M/apply.sql" || true; fi

NOW=1700000000
DAY=86400
for file in 001_cases 002_link_attribution 003_observable_index; do P -v ON_ERROR_STOP=1 -f "$D/$file.sql" >/dev/null; done
S "ALTER TABLE cases SET (autovacuum_enabled = false)"
S "INSERT INTO cases (tenant,id,title,severity,status,resolution,created_at,updated_at,version,tasks,observables,comments,history) VALUES
('acme','tp','t','low','closed','true_positive',1,10,2,'[]','[]','[]','[{\"kind\":\"closed\",\"at\":10}]'),
('acme','oth','t','low','closed','other',1,11,2,'[]','[]','[]','[{\"kind\":\"closed\",\"at\":11}]'),
('acme','fp','t','low','closed','false_positive',1,12,2,'[]','[]','[]','[{\"kind\":\"closed\",\"at\":12}]'),
('acme','ben','t','low','closed','benign',1,13,2,'[]','[]','[]','[{\"kind\":\"closed\",\"at\":13}]'),
('acme','reo','t','low','in_progress',NULL,1,14,3,'[]','[]','[]','[{\"kind\":\"closed\",\"at\":12},{\"kind\":\"reopened\",\"at\":14}]'),
('acme','newc','t','low','new',NULL,1,1,1,'[]','[]','[]','[]'),
('acme','scalar','t','low','closed','duplicate',1,15,2,'[]','[]','[]','[1,\"x\",null]'),
('beta','tp','t','low','closed','true_positive',1,10,2,'[]','[]','[]','[{\"kind\":\"closed\",\"at\":10}]'),
('beta','fp','t','low','closed','false_positive',1,12,2,'[]','[]','[]','[]')"
P -v ON_ERROR_STOP=1 -f "$D/004_close_columns.sql" >/dev/null
check "backfill closed_at equals updated_at on closed rows only" "7|0" "$(P -c "SELECT count(*) FILTER (WHERE closed_at = updated_at AND status = 'closed'), count(*) FILTER (WHERE closed_at IS NOT NULL AND status <> 'closed') FROM cases")"
check "backfill ever_incident: true positive, other, reopened, beta true positive" "acme/oth acme/reo acme/tp beta/tp" "$(P -c "SELECT string_agg(tenant || '/' || id, ' ' ORDER BY tenant, id) FROM cases WHERE ever_incident")"
check "CHECK refuses a closed row without closed_at" "1" "$(P -c "INSERT INTO cases (tenant,id,title,severity,status,created_at,updated_at,version,tasks,observables,comments,history) VALUES ('x','a','t','low','closed',1,1,1,'[]','[]','[]','[]')" 2>&1 | grep -c cases_closed_at_matches_status)"
check "CHECK refuses closed_at on an open row" "1" "$(P -c "UPDATE cases SET closed_at=5 WHERE id='newc'" 2>&1 | grep -c cases_closed_at_matches_status)"
check "CHECK refuses a negative closed_at" "1" "$(P -c "UPDATE cases SET closed_at=-1 WHERE id='tp' AND tenant='acme'" 2>&1 | grep -c 'closed_at_check')"
S "TRUNCATE cases CASCADE"

apply() {
    local id=$1 status=$2 resolution=$3 kind=$4 stamp=$5 version prior resolution_json change
    read -r version prior < <(P -F' ' -c "SELECT version, status FROM cases WHERE tenant='acme' AND id='$id'")
    if [[ "$resolution" == null ]]; then resolution_json=null; else resolution_json="\"$resolution\""; fi
    change="{\"status\":\"$status\",\"resolution\":$resolution_json,\"updated_at\":$stamp,\"event\":{\"kind\":\"$kind\",\"at\":$stamp},\"version\":$version,\"prior_status\":\"$prior\"}"
    P -v ch="$change" -f - <<SQL
PREPARE a(text,text,text,text) AS $(cat "$M/apply.sql");
EXECUTE a('acme','$id',:'ch','1000');
DEALLOCATE a;
SQL
}
show() { P -F' ' -c "SELECT status, coalesce(resolution,'-'), coalesce(closed_at::text,'NULL'), ever_incident FROM cases WHERE tenant='acme' AND id='$1'"; }
mk() { S "INSERT INTO cases (tenant,id,title,severity,status,created_at,updated_at,version,tasks,observables,comments,history,ever_incident) VALUES ('acme','$1','t','low','$2',1,1,1,'[]','[]','[]','[]',$3)"; }
for base in false true; do
    mk "s-$base" new "$base"
    apply "s-$base" in_progress null started 100 >/dev/null
    check "start keeps the flag ($base)" "in_progress - NULL $([[ $base == true ]] && echo t || echo f)" "$(show "s-$base")"
    for resolution in false_positive true_positive benign duplicate other; do
        incident=$base
        if [[ $resolution == true_positive || $resolution == other ]]; then incident=true; fi
        flag=$([[ $incident == true ]] && echo t || echo f)
        mk "n-$resolution-$base" new "$base"
        apply "n-$resolution-$base" closed "$resolution" closed 200 >/dev/null
        check "close from new as $resolution ($base)" "closed $resolution 200 $flag" "$(show "n-$resolution-$base")"
        apply "n-$resolution-$base" in_progress null reopened 300 >/dev/null
        check "reopen clears closed_at and keeps the flag ($resolution, $base)" "in_progress - NULL $flag" "$(show "n-$resolution-$base")"
        mk "i-$resolution-$base" in_progress "$base"
        apply "i-$resolution-$base" closed "$resolution" closed 200 >/dev/null
        check "close from in_progress as $resolution ($base)" "closed $resolution 200 $flag" "$(show "i-$resolution-$base")"
    done
    mk "r-$base" in_progress "$base"
    apply "r-$base" closed true_positive closed 5 >/dev/null
    apply "r-$base" in_progress null reopened 6 >/dev/null
    apply "r-$base" closed false_positive closed 7 >/dev/null
    check "true positive, reopen, false positive: still an incident ($base)" "closed false_positive 7 t" "$(show "r-$base")"
done
S "TRUNCATE cases CASCADE"

ind() {
    local tenant=$1 now=$2
    P -f - <<SQL | awk -F'|' '{ value = ($1 == "") ? "-" : sprintf("%.2f", $1); print value "|" $2 "|" $3 "|" $4 "|" $5 "|" $6 }'
PREPARE ind(text,text,text) AS $(cat "$M/indicator.sql");
EXECUTE ind('$tenant','$now','7776000');
DEALLOCATE ind;
SQL
}
case_row() {
    local tenant=$1 id=$2 status=$3 resolution=$4 created=$5 updated=$6 closed=$7 ever=$8 title=${9:-t}
    S "INSERT INTO cases (tenant,id,title,severity,status,resolution,created_at,updated_at,closed_at,ever_incident,version,tasks,observables,comments,history) VALUES ('$tenant','$id','$title','low','$status',$resolution,$created,$updated,$closed,$ever,1,'[]','[]','[]','[]')"
}

echo "== a: one case open 10 days; b: 1000 fast closures"
case_row a open1 new NULL $((NOW - 10 * DAY)) $((NOW - 10 * DAY)) NULL false
S "INSERT INTO cases (tenant,id,title,severity,status,resolution,created_at,updated_at,closed_at,ever_incident,version,tasks,observables,comments,history) SELECT 'b','f'||g,'t','low','closed','true_positive',$NOW-7200,$NOW-3600,$NOW-3600,true,2,'[]','[]','[]','[]' FROM generate_series(1,1000) g"
check "a reads its own open case: 240 h, open=1" "240.00|1|0|0|0|true" "$(ind a $NOW)"
check "b reads 1000 closures of 1 h" "1.00|0|1000|0|0|true" "$(ind b $NOW)"
check "a tenant without any case is empty with no case at all" "-|0|0|0|0|false" "$(ind nobody $NOW)"

echo "== closed true positive after 30 days, reopened, closed as false positive"
case_row c reopened closed "'false_positive'" $((NOW - 40 * DAY)) $((NOW - 5 * DAY)) $((NOW - 10 * DAY)) true
check "still counted through ever_incident: 720 h" "720.00|0|1|0|0|true" "$(ind c $NOW)"
echo "== true positive created 100 days ago, closed yesterday"
case_row d old closed "'true_positive'" $((NOW - 100 * DAY)) $((NOW - DAY)) $((NOW - DAY)) true
check "counted although created outside the window: 2376 h" "2376.00|0|1|0|0|true" "$(ind d $NOW)"
echo "== all false positive and benign"
case_row e e1 closed "'false_positive'" $((NOW - 3 * DAY)) $((NOW - 2 * DAY)) $((NOW - 2 * DAY)) false
case_row e e2 closed "'benign'" $((NOW - 3 * DAY)) $((NOW - 2 * DAY)) $((NOW - 2 * DAY)) false
check "no incident: empty figure, excluded=2" "-|0|0|0|2|true" "$(ind e $NOW)"
echo "== created in 2100 and closed before created"
case_row f future new NULL 4102444800 4102444800 NULL false
case_row g inverted closed "'true_positive'" $((NOW - DAY)) $((NOW - DAY)) $((NOW - 2 * DAY)) true
check "future created_at is worth the window, 2160 h, one bad" "2160.00|1|0|1|0|true" "$(ind f $NOW)"
check "closed before created is worth the window, never its age" "2160.00|0|1|1|0|true" "$(ind g $NOW)"
echo "== closed_at in the future"
case_row h skew closed "'true_positive'" $((NOW - DAY)) $((NOW - DAY)) $((NOW + DAY)) true
check "closed_at after now is bad: 2160 h" "2160.00|0|1|1|0|true" "$(ind h $NOW)"
echo "== updated_at differs from closed_at"
case_row i upd closed "'true_positive'" $((NOW - 5 * DAY)) $((NOW - 3 * DAY)) $((NOW - DAY)) true
check "the close time is closed_at (96 h), not updated_at (48 h)" "96.00|0|1|0|0|true" "$(ind i $NOW)"
echo "== a future updated_at does not move the figure or the open age"
case_row j fut new NULL $((NOW - DAY)) 4102444800 NULL false
check "open case of 24 h whatever updated_at" "24.00|1|0|0|0|true" "$(ind j $NOW)"
echo "== a title with ESC and 10 KB is never read"
case_row k big new NULL $((NOW - DAY)) $((NOW - DAY)) NULL false "$(printf '\033[31m%.0s' {1..1000})"
check "output is the integers and the figure" "24.00|1|0|0|0|true" "$(ind k $NOW)"
echo "== window edge: closed non-incident exactly at the window start is excluded, an incident one counted"
case_row l edge closed "'true_positive'" $((NOW - 91 * DAY)) $((NOW - 90 * DAY)) $((NOW - 90 * DAY)) true
check "closed_at = now - window counts, 24 h" "24.00|0|1|0|0|true" "$(ind l $NOW)"
case_row m old closed "'true_positive'" $((NOW - 200 * DAY)) $((NOW - 100 * DAY)) $((NOW - 100 * DAY)) true
check "closed 100 days ago and created 200 days ago is out of the window" "-|0|0|0|0|true" "$(ind m $NOW)"

if [[ -z "${MUTANT:-}" ]]; then
    echo "== the example, the clock and the GRC input"
    now_real="$(date +%s)"
    case_row n live new NULL $((now_real - 2 * 3600)) $((now_real - 2 * 3600)) NULL false
    /tmp/cases_indicators "$work/pg.yaml" n now >"$work/out.json" 2>"$work/err.txt" || true
    cat "$work/out.json"
    check "the example prints one object for tenant n" "1|incident.mean_hours_to_close" "$(jq -r '[length, .[0].name] | join("|")' "$work/out.json")"
    check "the figure is about 2 h" "true" "$(jq -r '.[0].value > 1.9 and .[0].value < 2.1' "$work/out.json")"
    check "observed_at is now, not a stored time" "true" "$(jq -r --argjson now "$now_real" '(.[0].observed_at | fromdateiso8601) - $now | fabs < 5' "$work/out.json")"
    check "the source is integers only" "true" "$(jq -r '.[0].source | test("^cases:computed=[0-9]+;open=1;closed=0;bad=0;excluded=0;window_days=90$")' "$work/out.json")"
    check "a now of 47 h ago is refused with nothing on stdout" "0|1" "$(/tmp/cases_indicators "$work/pg.yaml" n $((now_real - 47 * 3600)) 2>"$work/skew.txt" | wc -c | tr -d ' ' | tr '\n' '|')$(grep -c 'more than 300 seconds' "$work/skew.txt")"
    check "an empty tenant prints [] and one counts-only warning" "[]|no incident indicator emitted (no case at all): open=0;closed=0;bad=0;excluded=0" "$(/tmp/cases_indicators "$work/pg.yaml" nobody now 2>"$work/warn.txt" | tr -d '\n')|$(cat "$work/warn.txt")"
    cp "$work/out.json" /tmp/cases-indicators.json
fi

if [[ -z "${MUTANT:-}" && "${BIG:-1}" == 1 ]]; then
    echo "== plan at 1 000 000 cases, 100 000 open, before any ANALYZE (autovacuum off)"
    S "INSERT INTO cases (tenant,id,title,severity,status,resolution,created_at,updated_at,closed_at,ever_incident,version,tasks,observables,comments,history)
       SELECT 'big', 'c'||g, 't', 'low', CASE WHEN g % 10 = 0 THEN 'new' ELSE 'closed' END,
       CASE WHEN g % 10 = 0 THEN NULL ELSE (ARRAY['true_positive','false_positive','benign'])[1 + g % 3] END,
       $NOW - (g % 700) * $DAY - 7200, $NOW - (g % 700) * $DAY, CASE WHEN g % 10 = 0 THEN NULL ELSE $NOW - (g % 700) * $DAY END,
       g % 10 <> 0 AND g % 3 = 1, 2, '[]','[]','[]','[]' FROM generate_series(1,1000000) g"
    check "no statistics yet" "0" "$(P -c "SELECT count(*) FROM pg_stats WHERE tablename = 'cases'")"
    for tenant in fresh big; do
        [[ $tenant == fresh ]] && case_row fresh f1 new NULL $((NOW - DAY)) $((NOW - DAY)) NULL false
        echo "-- plan for tenant $tenant"
        P -f - <<SQL
PREPARE ind(text,text,text) AS $(cat "$M/indicator.sql");
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF) EXECUTE ind('$tenant','$NOW','7776000');
SQL
        echo "-- result for tenant $tenant: $(ind $tenant $NOW)"
    done
    check "still no statistics after the runs" "0" "$(P -c "SELECT count(*) FROM pg_stats WHERE tablename = 'cases'")"
fi
echo "FAILURES: $failures"
REMOTE
