#!/usr/bin/env bash
# Usage: [MUTANT=<name>] [BIG=1] crates/vuln-match/tests/indicator-live.sh <lab-state-dir>
# Live check of the KEV indicator on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the vuln_store, vuln_indicators and grc_evaluate
# examples, built for musl, run on the client VM against a scratch database; psql reads the real state back. MUTANT=<name> applies one SQL mutation of
# vuln_0006.sql (or of the Rust clock check, see MUTANTS) and the script must then report failures. BIG=1 adds the plan and timing proof at 2 M open and
# 1 M resolved rows under stale statistics.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: indicator-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
target="$here/target/x86_64-unknown-linux-musl/release/examples"
for name in vuln_store vuln_indicators grc_evaluate; do
    [[ -x "$target/$name" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p vuln-match -p grc --example $name" >&2; exit 2; }
done

database="vuln_ind_$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true' EXIT

for name in vuln_store vuln_indicators grc_evaluate; do
    scp "${ssh_options[@]}" "$target/$name" "$client_user@$client_address:/tmp/$name"
done
ssh "${ssh_options[@]}" "$client_user@$client_address" "rm -rf /tmp/vuln-migrations && mkdir /tmp/vuln-migrations"
scp "${ssh_options[@]}" "$here"/crates/vuln-match/migrations/vuln_000*.sql "$client_user@$client_address:/tmp/vuln-migrations/"
remote_status=0
ssh "${ssh_options[@]}" "$client_user@$client_address" "DATABASE=$database MUTANT=${MUTANT:-none} BIG=${BIG:-0} bash -s" <<'REMOTE' || remote_status=$?
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
vuln() { /tmp/vuln_store "$work/pg.yaml" "$@"; }
indicators() { /tmp/vuln_indicators "$work/pg.yaml" "$@"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
NOW=$(( $(date +%s) * 1000000 ))
NOW_SECONDS=$((NOW / 1000000))
stamp() { date -u -d "@$(( ($1) / 1000000 ))" +%Y-%m-%dT%H:%M:%SZ; }
DAY=86400000000
HOUR=3600000000
MINUTE=60000000
ind() { sql "SELECT figure||'|'||n_open||'|'||n_resolved||'|'||n_cleared||'|'||n_bad||'|'||n_over_30||'|'||oldest_open_days||'|'||observed_micros FROM vuln_kev_indicator('$1', ${2:-$NOW})"; }
ins() { sql "INSERT INTO vuln_findings (tenant, asset, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority, first_seen_micros, last_seen_micros, resolved_micros, kev_since_micros) VALUES ('$1', '$2', 'e', '$3', 'R', '1', '2', 5, 0.5, $4, 100, $5, $6, $7, $8)"; }

vuln migrate
if [[ "$MUTANT" != none ]]; then
    f=/tmp/vuln-migrations/vuln_0006.sql
    cp "$f" "$work/mutant.sql"
    case "$MUTANT" in
        drop_open) sed -i 's/AND f.kev_since_micros IS NOT NULL AND f.resolved_micros IS NULL/& AND false/' "$work/mutant.sql" ;;
        bad_as_zero) sed -i 's/WHEN t.bad THEN greatest(7776000000000, CASE WHEN t.first_seen <= now_micros THEN now_micros - t.first_seen ELSE 0 END)/WHEN t.bad THEN 0/' "$work/mutant.sql" ;;
        observed_now) sed -i 's/(SELECT s.oldest FROM open_seen s)/now_micros/' "$work/mutant.sql" ;;
        no_tenant_open) sed -i 's/WHERE f.tenant = tenant_name AND f.kev_since_micros IS NOT NULL AND f.resolved_micros IS NULL/WHERE f.kev_since_micros IS NOT NULL AND f.resolved_micros IS NULL/' "$work/mutant.sql" ;;
        no_tenant_resolved) sed -i 's/WHERE f.tenant = tenant_name AND f.kev_since_micros IS NOT NULL AND f.resolved_micros >=/WHERE f.kev_since_micros IS NOT NULL AND f.resolved_micros >=/' "$work/mutant.sql" ;;
        no_tenant_seen) sed -i 's/WHERE o.tenant = tenant_name AND o.resolved_micros IS NULL/WHERE o.resolved_micros IS NULL/' "$work/mutant.sql" ;;
        no_tenant_last) sed -i 's/WHERE r.tenant = tenant_name AND r.resolved_micros IS NOT NULL/WHERE r.resolved_micros IS NOT NULL/' "$work/mutant.sql" ;;
        read_kev) sed -i 's/f.kev_since_micros IS NOT NULL/f.kev/g' "$work/mutant.sql" ;;
        cap_90) sed -i 's/WHEN t.bad THEN greatest(7776000000000, CASE WHEN t.first_seen <= now_micros THEN now_micros - t.first_seen ELSE 0 END)/WHEN t.bad THEN 7776000000000/' "$work/mutant.sql" ;;
        observed_kev_only) sed -i 's/WHERE o.tenant = tenant_name AND o.resolved_micros IS NULL/& AND o.kev_since_micros IS NOT NULL/' "$work/mutant.sql" ;;
        observed_bad_rows) sed -i 's/AND o.first_seen_micros <= now_micros AND o.last_seen_micros <= now_micros AND o.last_seen_micros >= o.first_seen_micros//' "$work/mutant.sql" ;;
        window_open) sed -i 's/f.resolved_micros >= now_micros - 7776000000000/f.resolved_micros IS NOT NULL/' "$work/mutant.sql" ;;
        window_strict) sed -i 's/f.resolved_micros >= now_micros - 7776000000000/f.resolved_micros > now_micros - 7776000000000/' "$work/mutant.sql" ;;
        bad_resolved_last) sed -i 's/ OR p.resolved < p.last_seen)/)/' "$work/mutant.sql" ;;
        bad_last_seen) sed -i 's/ OR p.last_seen > now_micros//' "$work/mutant.sql" ;;
        bad_first_future) sed -i 's/(p.first_seen > now_micros OR /(/' "$work/mutant.sql" ;;
        float_figure) sed -i 's/round(sum(w.micros) \/ count(\*) \/ 86400000000, 6)::text/(avg(w.micros::float8) \/ 86400000000)::text/' "$work/mutant.sql" ;;
        last_resolved_any) sed -i 's/AND r.resolved_micros >= r.last_seen_micros//' "$work/mutant.sql" ;;
        *) echo "unknown mutant $MUTANT"; exit 2 ;;
    esac
    if cmp -s "$f" "$work/mutant.sql"; then echo "mutant $MUTANT changed nothing"; exit 2; fi
    sql "DROP FUNCTION vuln_kev_indicator(text, bigint)"
    psql -X -q -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" -f "$work/mutant.sql"
    echo "mutant $MUTANT applied"
fi
check "function is STABLE with the pins" "s|{\"search_path=pg_catalog, public, pg_temp\",enable_seqscan=off,enable_bitmapscan=off,enable_sort=off,jit=off}" \
    "$(sql "SELECT provolatile::text || '|' || proconfig::text FROM pg_proc WHERE proname = 'vuln_kev_indicator'")"

echo "--- fixtures"
ins a h1 a1 true $((NOW - 60 * DAY)) $((NOW - HOUR)) NULL $((NOW - 60 * DAY))
ins a h1 a2 false $((NOW - 100 * DAY)) $((NOW - 2 * HOUR)) NULL NULL
sql "INSERT INTO vuln_findings (tenant, asset, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority, first_seen_micros, last_seen_micros, resolved_micros, kev_since_micros)
     SELECT 'b', 'h' || (g % 7), 'e', 'p' || g, 'R', '1', '2', 5, 0.5, true, 100, $((NOW - 2 * DAY)), $((NOW - 2 * DAY + 30 * MINUTE)), $((NOW - 2 * DAY + HOUR)), $((NOW - 2 * DAY)) FROM generate_series(1, 1000) g"
ins clean h1 c1 false $((NOW - 30 * DAY)) $((NOW - 3 * HOUR)) NULL NULL
ins mix h1 m1 true $((NOW - 40 * DAY)) $((NOW - HOUR)) NULL $((NOW - 40 * DAY))
ins mix h1 m2 false $((NOW - 10 * DAY)) $((NOW - 30 * MINUTE)) NULL $((NOW - 10 * DAY))
ins mix h2 m3 true $((NOW - 20 * DAY)) $((NOW - 10 * DAY)) $((NOW - 10 * DAY)) $((NOW - 20 * DAY))
ins mix h2 m4 true $((NOW - 120 * DAY)) $((NOW - 95 * DAY)) $((NOW - 90 * DAY - 1)) $((NOW - 120 * DAY))
ins mix h2 m6 true $((NOW - 100 * DAY)) $((NOW - 95 * DAY)) $((NOW - 90 * DAY)) $((NOW - 100 * DAY))
ins bad2100 h1 g1 true $((NOW - 10 * DAY)) $((NOW - HOUR)) NULL $((NOW - 10 * DAY))
ins bad2100 h2 g2 true 4102444800000000 $((NOW - 5 * HOUR)) NULL 4102444800000000
ins old h1 o1 true $((NOW - 200 * DAY)) $((NOW + MINUTE)) NULL $((NOW - 200 * DAY))
ins old h2 o2 true $((NOW - 10 * DAY)) $((NOW - HOUR)) NULL $((NOW - 10 * DAY))
ins back h1 b1 true $((NOW - 30 * DAY)) $((NOW - DAY)) $((NOW - 2 * DAY)) $((NOW - 30 * DAY))
ins silent h1 s1 true $((NOW - 5 * DAY)) $((NOW - 49 * HOUR)) NULL $((NOW - 5 * DAY))
ins back2 h1 x1 false $((NOW - 10 * DAY)) $((NOW - 100 * DAY)) NULL NULL
ins frac h1 f1 true $((NOW - 3 * DAY)) $((NOW - 2 * DAY)) $((NOW - 2 * DAY)) $((NOW - 3 * DAY))
ins frac h1 f2 true $((NOW - 3 * DAY)) $((NOW - 2 * DAY)) $((NOW - 2 * DAY)) $((NOW - 3 * DAY))
ins frac h1 f3 true $((NOW - 4 * DAY)) $((NOW - 2 * DAY)) $((NOW - 2 * DAY)) $((NOW - 4 * DAY))

echo "--- figures"
check "a: one KEV open 60 days, the older non-KEV row sets observed_at, b never moves it" "60.000000|1|0|0|0|1|60|$((NOW - 2 * HOUR))" "$(ind a)"
check "b: 1000 fast fixes alone" "0.041667|0|1000|0|0|0|0|$((NOW - 2 * DAY + HOUR))" "$(ind b)"
check "a: never fixed, ten days later the age grew" "70.000000" "$(ind a $((NOW + 10 * DAY)) | cut -d'|' -f1)"
check "no scan stored: nothing to observe" "0|0|0|0|0|0|0|" "$(ind none)"
check "scans without KEV: figure 0 with observed_at" "0|0|0|0|0|0|0|$((NOW - 3 * HOUR))" "$(ind clean)"
check "mix: open KEV, a cleared KEV flag, resolved in window and at its edge, one outside" "17.500000|2|2|1|0|1|40|$((NOW - HOUR))" "$(ind mix)"
check "a first_seen in 2100 is bad and worth 90 days, never 0, and never feeds observed_at" "50.000000|1|0|0|1|0|10|$((NOW - HOUR))" "$(ind bad2100)"
check "a 200-day row with last_seen in the future is worth 200 days, not observed" "105.000000|1|0|0|1|0|10|$((NOW - HOUR))" "$(ind old)"
check "resolved before last_seen is bad, worth 90, and nothing is observed" "90.000000|0|0|0|1|0|0|" "$(ind back)"
check "one silent asset: observed_at is 49 hours old" "5.000000|1|0|0|0|0|5|$((NOW - 49 * HOUR))" "$(ind silent)"
check "a bad non-KEV row is never observed" "0|0|0|0|0|0|0|" "$(ind back2)"
check "fractional mean is rounded to 6 digits in numeric" "1.333333" "$(ind frac | cut -d'|' -f1)"

echo "--- hostile text is refused at the store, never in the output"
check "ESC in an asset is refused by the CHECK" "refused" "$(sql "INSERT INTO vuln_findings (tenant, asset, ecosystem, package, record_id, installed_version, cvss, epss, kev, priority, first_seen_micros, last_seen_micros) VALUES ('esc', E'a\\x1bb', 'e', 'p', 'R', '1', 5, 0.5, true, 1, 1, 1)" >/dev/null 2>&1 && echo stored || echo refused)"
check "10 KB asset is refused by the CHECK" "refused" "$(sql "INSERT INTO vuln_findings (tenant, asset, ecosystem, package, record_id, installed_version, cvss, epss, kev, priority, first_seen_micros, last_seen_micros) VALUES ('big10k', repeat('a', 10000), 'e', 'p', 'R', '1', 5, 0.5, true, 1, 1, 1)" >/dev/null 2>&1 && echo stored || echo refused)"

echo "--- the example and the output file"
now_real="$NOW"
check "the output has the contract shape for a" '[{"name":"vuln.kev_mean_days_to_fix","observed_at":"'"$(stamp $((NOW - 2 * HOUR)))"'","source":"vuln:computed='"$NOW_SECONDS"';kev_open=1;kev_resolved=0;kev_cleared=0;bad_time_rows=0;open_over_30=1;oldest_open_days=60;window_days=90","tenant":"a","value":60.0}]' "$(indicators a $NOW)"
check "no scan stored: the file is [] and the counts line is on stderr" "[]|no vulnerability indicator emitted: kev_open=0;kev_resolved=0;kev_cleared=0;bad_time_rows=0;open_over_30=0;oldest_open_days=0;window_days=90" \
    "$(indicators none $NOW 2>"$work/err" | tr -d '\n')|$(tr -d '\n' <"$work/err")"
check "the back-clock tenant emits nothing" "[]" "$(indicators back $NOW 2>/dev/null)"
out_before="$(indicators frac $NOW)"
sql "ALTER DATABASE $DATABASE SET extra_float_digits = 3"
check "extra_float_digits set on the database: the value is byte-equal" "$out_before" "$(indicators frac $NOW)"
sql "ALTER DATABASE $DATABASE SET extra_float_digits = -15"
check "extra_float_digits -15: the value is byte-equal" "$out_before" "$(indicators frac $NOW)"
check "extra_float_digits through the environment: byte-equal" "$out_before" "$(PGOPTIONS='-c extra_float_digits=0' indicators frac $NOW)"
sql "ALTER DATABASE $DATABASE RESET extra_float_digits"
check "a now of 47 hours ago is refused with no output" "refused|" "$(indicators a $((now_real - 47 * HOUR)) 2>/dev/null >"$work/skew.out" && echo accepted || echo refused)|$(cat "$work/skew.out")"
check "a now of 47 hours ago names the clock skew" "the given time differs from the database clock by more than 300 seconds" "$(indicators a $((now_real - 47 * HOUR)) 2>&1 >/dev/null || true)"
check "a now within the skew is accepted" "accepted" "$(indicators a $((now_real - 200 * 1000000)) >/dev/null 2>&1 && echo accepted || echo refused)"
check "a bad tenant name is refused" "refused" "$(indicators '-x' $NOW >/dev/null 2>&1 && echo accepted || echo refused)"

echo "--- end to end through vuln_store scan and GRC"
vuln scan k h1 $((NOW - 60 * DAY)) 100 100 x/R1/kev y/R2 >/dev/null
vuln scan k h1 $((NOW - 59 * DAY)) 100 100 x/R1/kev y/R2 >/dev/null
vuln scan k h1 $((NOW - HOUR)) 100 100 x/R1/kev y/R2 >/dev/null
check "scan stored KEV: the figure reads 60 days" "60.000000|1|0|0|0|1|60|$((NOW - HOUR))" "$(ind k)"
vuln scan k h1 $((NOW - MINUTE)) 100 100 x/R1 y/R2 >/dev/null
check "a rescan with kev = false leaves the figure unchanged but counts the cleared flag" "60.000000|1|0|1|0|1|60|$((NOW - HOUR))" "$(ind k)"
check "kev is false and kev_since is kept" "false|true" "$(sql "SELECT kev::text || '|' || (kev_since_micros IS NOT NULL)::text FROM vuln_findings WHERE tenant = 'k' AND package = 'x'")"
vuln scan k h1 $NOW 100 100 y/R2 >/dev/null
check "x fixed: the 60-day fix stays, mean of one resolved row" "60.000000|0|1|1|0|0|0|$NOW" "$(ind k)"
indicators k $NOW >"$work/k.json"
cat "$work/k.json"
printf 'evidence: []\n' >"$work/manual.yaml"
/tmp/grc_evaluate builtin:nis2 "$work/k.json" "$work/manual.yaml" k "$(stamp $NOW)" --format json --out "$work/nis2.json" || true
echo "grc art21-2-e for k (fresh):"
jq -c '.controls[] | select(.id == "art21-2-e") | {id, status, evidence_time}' "$work/nis2.json" || true
indicators silent $NOW >"$work/silent.json"
cat "$work/silent.json"
/tmp/grc_evaluate builtin:nis2 "$work/silent.json" "$work/manual.yaml" silent "$(stamp $NOW)" --format json --out "$work/silent-nis2.json" || true
echo "grc art21-2-e for silent (49 h old):"
jq -c '.controls[] | select(.id == "art21-2-e") | {id, status, evidence_time}' "$work/silent-nis2.json" || true
indicators a $NOW >"$work/a.json"
/tmp/grc_evaluate builtin:nis2 "$work/a.json" "$work/manual.yaml" a "$(stamp $NOW)" --format json --out "$work/a-nis2.json" || true
echo "grc art21-2-e for a (60 days, observed 2 h old):"
jq -c '.controls[] | select(.id == "art21-2-e") | {id, status, evidence_time}' "$work/a-nis2.json" || true
indicators b $NOW >"$work/b.json"
/tmp/grc_evaluate builtin:nis2 "$work/b.json" "$work/manual.yaml" b "$(stamp $NOW)" --format json --out "$work/b-nis2.json" || true
echo "grc art21-2-e for b (fast fixes, observed 47 h old):"
jq -c '.controls[] | select(.id == "art21-2-e") | {id, status, evidence_time}' "$work/b-nis2.json" || true

if [[ "$BIG" == 1 ]]; then
    echo "--- 2 M open plus 1 M in-window resolved rows, all KEV, 128-byte assets, stale statistics"
    sql "ALTER TABLE vuln_findings SET (autovacuum_enabled = false)"
    sql "INSERT INTO vuln_findings (tenant, asset, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority, first_seen_micros, last_seen_micros, resolved_micros, kev_since_micros)
         SELECT 'big', 'h' || lpad((g % 5000)::text, 127, 'x'), 'e', 'p' || g, 'R', '1', '2', 5, 0.5, true, 100 + g % 1000, $((NOW - 100 * DAY)) + g::bigint * 1000, $((NOW - HOUR)) - g % 1000, NULL, $((NOW - 100 * DAY)) + g::bigint * 1000
         FROM generate_series(1, 2000000) g"
    sql "INSERT INTO vuln_findings (tenant, asset, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority, first_seen_micros, last_seen_micros, resolved_micros, kev_since_micros)
         SELECT 'big', 'r' || lpad((g % 5000)::text, 127, 'y'), 'e', 'q' || g, 'R', '1', '2', 5, 0.5, true, 100, $((NOW - 120 * DAY)), $((NOW - 81 * DAY)), $((NOW - 80 * DAY)) + g::bigint * 5000000, $((NOW - 120 * DAY))
         FROM generate_series(1, 1000000) g"
    check "rows of the big tenant" "2000000|1000000|2000000|1000000" "$(sql "SELECT count(*) FILTER (WHERE resolved_micros IS NULL) || '|' || count(*) FILTER (WHERE resolved_micros IS NOT NULL) || '|' || count(*) FILTER (WHERE resolved_micros IS NULL AND kev_since_micros IS NOT NULL) || '|' || count(*) FILTER (WHERE resolved_micros IS NOT NULL AND kev_since_micros IS NOT NULL) FROM vuln_findings WHERE tenant = 'big'")"
    echo "statistics of the table are stale: last analyze"
    sql "SELECT coalesce(last_analyze::text, 'never') || '|' || coalesce(last_autoanalyze::text, 'never') FROM pg_stat_user_tables WHERE relname = 'vuln_findings'"
    echo "big tenant statement, five times through PREPARE/EXECUTE before any ANALYZE (wall time of each in ms):"
    for i in 1 2 3; do
        start="$(date +%s%N)"
        ind big >/dev/null
        echo "  run $i: $(( ($(date +%s%N) - start) / 1000000 )) ms"
    done
    echo "$(ind big)"
    echo "fresh tenant with no row: $(ind fresh)"
fi

echo "failures=$failures"
exit "$failures"
REMOTE
if [[ "${BIG:-0}" == 1 ]]; then
    echo "--- plans of the statement under auto_explain, stale statistics (autovacuum off, no ANALYZE since the load)"
    now_seconds="$(date +%s)"
    ssh "${ssh_options[@]}" "$datastore_user@$datastore_address" "sudo -u postgres psql -X -q -tA -d $database" <<SQL || remote_status=$?
LOAD 'auto_explain';
PREPARE ind(text, bigint) AS SELECT * FROM vuln_kev_indicator(\$1, \$2);
EXECUTE ind('big', ${now_seconds}000000);
EXECUTE ind('big', ${now_seconds}000000);
EXECUTE ind('big', ${now_seconds}000000);
EXECUTE ind('big', ${now_seconds}000000);
EXECUTE ind('big', ${now_seconds}000000);
SET auto_explain.log_min_duration = 0;
SET auto_explain.log_nested_statements = on;
SET auto_explain.log_analyze = on;
SET auto_explain.log_buffers = on;
SET client_min_messages = log;
SELECT 'big: ' || figure || '|' || n_open || '|' || n_resolved FROM vuln_kev_indicator('big', ${now_seconds}000000);
SELECT 'fresh: ' || figure || '|' || n_open FROM vuln_kev_indicator('fresh', ${now_seconds}000000);
SQL
fi
exit "$remote_status"
