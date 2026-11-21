#!/usr/bin/env bash
# Usage: crates/vuln-match/tests/store-live.sh <lab-state-dir>
# Live check of the vuln findings store on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the vuln_store example, built for musl, runs on
# the client VM against a scratch database of the datastore VM and psql reads the real state back: scan, resolve, tenant isolation, the cap at commit
# under concurrent scans, one asset scanned concurrently, paging of 1 200 rows, a longest-key cursor and refusals.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: store-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
binary="$here/target/x86_64-unknown-linux-musl/release/examples/vuln_store"
[[ -x "$binary" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p vuln-match --example vuln_store" >&2; exit 2; }

database="vuln_live_$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
old_database="${database}_old"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$old_database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database; sudo -u postgres dropdb --if-exists $old_database" || true' EXIT

scp "${ssh_options[@]}" "$binary" "$client_user@$client_address:/tmp/vuln_store"
ssh "${ssh_options[@]}" "$client_user@$client_address" "rm -rf /tmp/vuln-migrations && mkdir /tmp/vuln-migrations"
scp "${ssh_options[@]}" "$here"/crates/vuln-match/migrations/vuln_000*.sql "$client_user@$client_address:/tmp/vuln-migrations/"
ssh "${ssh_options[@]}" "$client_user@$client_address" "DATABASE=$database OLD_DATABASE=$old_database bash -s" <<'REMOTE'
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
sql_old() { psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$OLD_DATABASE" "$@"; }
vuln() { /tmp/vuln_store "$work/pg.yaml" "$@"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
open_rows() { sql "SELECT count(*) FROM vuln_findings WHERE tenant = '$1' AND resolved_micros IS NULL"; }
all_rows() { sql "SELECT count(*) FROM vuln_findings WHERE tenant = '$1'"; }
counter() { sql "SELECT coalesce((SELECT open_total || '/' || resolved_total FROM vuln_finding_rows WHERE tenant = '$1'), '-1')"; }
real_counter() { sql "SELECT count(*) FILTER (WHERE resolved_micros IS NULL) || '/' || count(*) FILTER (WHERE resolved_micros IS NOT NULL) FROM vuln_findings WHERE tenant = '$1'"; }
open_counter() { counter "$1" | cut -d/ -f1; }
fields() { vuln "$@" | sed -E 's/ScanOutcome \{ inserted: ([0-9]+), updated: ([0-9]+), resolved: ([0-9]+), refused_no_room: ([0-9]+), evicted_resolved: ([0-9]+), refused: ([0-9]+), duplicates: ([0-9]+) \}/\1|\2|\3|\4|\5|\6/'; }
duplicates_of() { vuln "$@" | sed -E 's/.*duplicates: ([0-9]+) \}/\1/'; }
asset_counter() { sql "SELECT coalesce((SELECT resolved_total FROM vuln_asset_resolved WHERE tenant = '$1' AND asset = '$2'), -1)"; }
real_asset_counter() { sql "SELECT count(*) FROM vuln_findings WHERE tenant = '$1' AND asset = '$2' AND resolved_micros IS NOT NULL"; }
asset_counters_equal() { sql "SELECT count(*) FROM (SELECT tenant, asset, count(*) AS n FROM vuln_findings WHERE resolved_micros IS NOT NULL GROUP BY tenant, asset) c FULL JOIN vuln_asset_resolved w USING (tenant, asset) WHERE coalesce(c.n, 0) <> coalesce(w.resolved_total, 0)"; }
NOW=1700000000000000
CAP=2000000
RCAP=1000000
HOUR=3600000000

vuln migrate
check "migration applied: function and tables exist" "1|1|1|1" "$(sql "SELECT (SELECT count(*) FROM pg_proc WHERE proname = 'vuln_scan_store') || '|' || count(*) || '|' || (SELECT count(*) FROM pg_class WHERE relname = 'vuln_finding_rows') || '|' || (SELECT count(*) FROM pg_class WHERE relname = 'vuln_asset_resolved') FROM pg_class WHERE relname = 'vuln_findings'")"
echo "columns: inserted|updated|resolved|no_room|evicted|refused (duplicates read apart)"

check "scan 1 of h1 stores 3" "3|0|0|0|0|0" "$(fields scan a h1 $NOW $CAP $RCAP openssl/R1 curl/R2 zlib/R3)"
check "tenant a open rows" 3 "$(open_rows a)"
first_seen="$(sql "SELECT first_seen_micros FROM vuln_findings WHERE tenant = 'a' AND package = 'curl'")"
check "scan 2 without zlib resolves it, the two seen rows are not rewritten" "0|0|1|0|0|0" "$(fields scan a h1 $((NOW + 1000)) $CAP $RCAP openssl/R1 curl/R2)"
echo "psql read-back:"
sql "SELECT package, first_seen_micros - $NOW, last_seen_micros - $NOW, coalesce(resolved_micros - $NOW, -1) FROM vuln_findings WHERE tenant = 'a' ORDER BY package"
check "zlib resolved at scan 2" "1000" "$(sql "SELECT resolved_micros - $NOW FROM vuln_findings WHERE tenant = 'a' AND package = 'zlib'")"
check "curl last seen untouched inside the granularity" "$first_seen|$NOW" "$(sql "SELECT first_seen_micros || '|' || last_seen_micros FROM vuln_findings WHERE tenant = 'a' AND package = 'curl'")"
check "open rows after scan 2" 2 "$(open_rows a)"
check "an hour later the two seen rows move their last seen" "0|2|0|0|0|0" "$(fields scan a h1 $((NOW + HOUR + 1000)) $CAP $RCAP openssl/R1 curl/R2)"
check "curl first seen kept, last seen moved" "$first_seen|$((NOW + HOUR + 1000))" "$(sql "SELECT first_seen_micros || '|' || last_seen_micros FROM vuln_findings WHERE tenant = 'a' AND package = 'curl'")"
check "zlib seen again clears the resolution" "0|1|0|0|0|0" "$(fields scan a h1 $((NOW + HOUR + 2000)) $CAP $RCAP zlib/R3 openssl/R1 curl/R2)"
check "all three open again" 3 "$(open_rows a)"
check "scan of h1 with only zlib resolves the others" "0|0|2|0|0|0" "$(fields scan a h1 $((NOW + HOUR + 3000)) $CAP $RCAP zlib/R3)"
check "other asset unaffected: h2 scan of a" "1|0|0|0|0|0" "$(fields scan a h2 $NOW $CAP $RCAP openssl/R1)"
check "h1 scan does not resolve h2" 1 "$(sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'a' AND asset = 'h2' AND resolved_micros IS NULL")"
check "counter equals the real counts" "$(real_counter a)" "$(counter a)"
check "per-asset counts equal the real counts after the first section" 0 "$(asset_counters_equal)"
echo "--- duplicate keys of one scan are merged and counted"
check "3 copies of one key give duplicates=2" 2 "$(duplicates_of scan dup h1 $NOW $CAP $RCAP x/R1 x/R1 x/R1)"
check "one row is stored" 1 "$(all_rows dup)"
check "a scan without a repeat counts none" 0 "$(duplicates_of scan dup h1 $((NOW + 1)) $CAP $RCAP x/R1 y/R2)"

check "tenant b starts empty" 0 "$(all_rows b)"
before_a="$(sql "SELECT md5(string_agg(t::text, ',' ORDER BY package, asset)) FROM vuln_findings t WHERE tenant = 'a'")"
check "tenant b scan of the same keys inserts" "2|0|0|0|0|0" "$(fields scan b h1 $NOW $CAP $RCAP openssl/R1 curl/R2)"
check "tenant a rows untouched by tenant b" "$before_a" "$(sql "SELECT md5(string_agg(t::text, ',' ORDER BY package, asset)) FROM vuln_findings t WHERE tenant = 'a'")"
fields scan a h1 $((NOW + HOUR + 4000)) $CAP $RCAP >/dev/null
check "tenant a empty scan leaves tenant b open" 2 "$(open_rows b)"

echo "--- cap at commit, two assets of one tenant at open cap minus one"
check "seed 9 of cap 10" "9|0|0|0|0|0" "$(fields bulk c s0 $NOW 10 $RCAP 9 seed)"
fields bulk c x1 $NOW 10 $RCAP 5 xa >"$work/x.out" &
first=$!
fields bulk c y1 $NOW 10 $RCAP 5 ya >"$work/y.out" &
second=$!
wait "$first" "$second"
check "open rows exactly at the cap" 10 "$(open_rows c)"
check "counter at the cap" "10/0" "$(counter c)"
check "inserted of the two scans sum to 1" 1 "$(cat "$work/x.out" "$work/y.out" | awk -F'|' '{s += $1} END {print s}')"
check "refused_no_room of the two scans sum to 9" 9 "$(cat "$work/x.out" "$work/y.out" | awk -F'|' '{s += $4} END {print s}')"
check "a full tenant does not block another tenant" "5|0|0|0|0|0" "$(fields bulk d s0 $NOW 10 $RCAP 5 other)"
check "a full tenant still accepts an unchanged scan" "0|0|0|0|0|0" "$(fields bulk c s0 $((NOW + 1)) 10 $RCAP 9 seed)"
check "a scan of a full tenant refuses only new rows" "0|0|0|3|0|0" "$(fields bulk c z1 $NOW 10 $RCAP 3 zz)"
check "counter still equals the real counts for every tenant" 0 "$(sql "SELECT count(*) FROM (SELECT tenant, count(*) FILTER (WHERE resolved_micros IS NULL) AS o, count(*) FILTER (WHERE resolved_micros IS NOT NULL) AS r FROM vuln_findings GROUP BY tenant) c JOIN vuln_finding_rows w USING (tenant) WHERE (w.open_total, w.resolved_total) <> (c.o, c.r)")"

echo "--- resolved history does not fill the open cap (starve)"
check "good asset stores 2" "2|0|0|0|0|0" "$(fields scan st good $NOW 10 4 openssl/R1 curl/R2)"
check "evil scan 1" "3|0|0|0|0|0" "$(fields bulk st evil $((NOW + 1)) 10 4 3 e0x)"
check "evil scan 2 swaps inventory, 3 resolved" "3|0|3|0|0|0" "$(fields bulk st evil $((NOW + 2)) 10 4 3 e1x)"
check "evil scan 3 swaps again, resolved history over cap 4 evicts the oldest 2" "3|0|3|0|2|0" "$(fields bulk st evil $((NOW + 3)) 10 4 3 e2x)"
check "evil scan 4 evicts 3 more" "3|0|3|0|3|0" "$(fields bulk st evil $((NOW + 4)) 10 4 3 e3x)"
check "good asset finds a new vulnerability and it is stored" "1|0|0|0|0|0" "$(fields scan st good $((NOW + 5)) 10 4 openssl/R1 curl/R2 zlib/R3)"
check "resolved rows at the cap, counter equals count" "$(real_counter st)" "$(counter st)"
check "per-asset counts equal the real counts after the tenant eviction" 0 "$(asset_counters_equal)"
check "resolved rows are 4" 4 "$(sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'st' AND resolved_micros IS NOT NULL")"
check "the oldest resolved rows were the ones deleted" "0" "$(sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'st' AND resolved_micros = $((NOW + 2))")"

echo "--- six concurrent scans of one asset"
for letter in a b c d e f; do
    fields bulk e h1 $((NOW + 10)) $CAP $RCAP 50 "p$letter" >"$work/e-$letter.out" &
done
wait
check "one scan is the full truth: 50 open rows" 50 "$(open_rows e)"
check "the open rows all come from one scan" 1 "$(sql "SELECT count(DISTINCT substring(package from '^[a-z]+')) FROM vuln_findings WHERE tenant = 'e' AND resolved_micros IS NULL")"
check "counter equals rows" "$(real_counter e)" "$(counter e)"

echo "--- paging and refusals"
check "bulk 1200 stored" "1200|0|0|0|0|0" "$(fields bulk p h1 $NOW $CAP $RCAP 1200 pkg)"
check "limit 500 pages through 1200 rows" "pages=3 rows=1200" "$(vuln pages p 500)"
long="$(printf 'k%.0s' $(seq 1 128))"
long_package="$(printf 'q%.0s' $(seq 1 127))"
check "longest keys stored" "2|0|0|0|0|0" "$(fields scan l "$long" $NOW $CAP $RCAP "$long_package"1/"$long" "$long_package"2/"$long")"
check "longest cursor pages on" "pages=2 rows=2" "$(vuln pages l 1)"
check "ESC in a package is refused alone" "1|0|0|0|0|1" "$(fields scan m h1 $NOW $CAP $RCAP $'bad\033pkg/R1' good/R2)"
check "a leading dash is refused alone" "1|0|0|0|0|1" "$(fields scan m2 h1 $NOW $CAP $RCAP -rf/R1 good/R2)"
check "only the good one is stored" 1 "$(all_rows m)"
check "50 001 findings refused before any I/O" "refused" "$(vuln bulk n h1 $NOW $CAP $RCAP 50001 big >/dev/null 2>&1 && echo stored || echo refused)"
check "nothing stored for the refused scan" "0|-1" "$(all_rows n)|$(counter n)"
check "a cap of 0 is refused" "refused" "$(vuln scan n h1 $NOW 0 $RCAP a/R1 >/dev/null 2>&1 && echo stored || echo refused)"

echo "--- two tenants whose names collided under the old two-int4 lock never wait on each other"
collide_a=t1481
collide_b=t45040
check "the two names hash to the same 32-bit value" "1" "$(sql "SELECT (hashtext('$collide_a') = hashtext('$collide_b'))::int")"
check "the 64-bit keys differ" "0" "$(sql "SELECT (hashtextextended('vuln_scan_store/$collide_a', 0) = hashtextextended('vuln_scan_store/$collide_b', 0))::int")"
sql "SET application_name = 'vuln_holder'; BEGIN; SELECT * FROM vuln_scan_store('$collide_a', 'h1', '[]'::jsonb, 10, 1, 10, 1, 10); SELECT pg_sleep(600); COMMIT;" >/dev/null 2>&1 &
holder=$!
held=0
for _ in $(seq 1 60); do
    held="$(sql "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE a.application_name = 'vuln_holder' AND l.locktype = 'advisory' AND l.granted")"
    [[ "$held" == 1 ]] && break
    sleep 1
done
check "the holder owns its tenant lock" 1 "$held"
check "the other tenant scans while the first holds its lock" "1|0|0|0|0|0" "$(fields scan $collide_b h1 $NOW $CAP $RCAP openssl/R1)"
check "the holder still holds its lock after that scan finished" 1 "$(sql "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE a.application_name = 'vuln_holder' AND l.locktype = 'advisory' AND l.granted")"
sql "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'vuln_holder'" >/dev/null
wait "$holder" || true

echo "--- cost does not grow with the tenant: one finding into a tenant with 200000 rows, and 50 000 unchanged"
sql "INSERT INTO vuln_findings SELECT 'big', 'bulk' || (g % 4), 'Debian:12', 'seedpkg' || g, 'R1', '1.0', '1.1', 5, 0.5, false, 1000 + g % 50, 1, 1, NULL FROM generate_series(1, 200000) g"
check "a tenant with no counter row yet bootstraps it once" "1|0|0|0|0|0" "$(fields scan big hostA $NOW $CAP $RCAP openssl/R1)"
check "bootstrapped counter equals the real counts" "$(real_counter big)" "$(counter big)"
start_one="$(date +%s%N)"
check "one more finding" "1|0|0|0|0|0" "$(fields scan big hostA $((NOW + 1)) $CAP $RCAP openssl/R1 curl/R2)"
echo "one-finding scan in a 200 000 row tenant took $(( ($(date +%s%N) - start_one) / 1000000 )) ms"
start_big="$(date +%s%N)"
check "50 000 findings, first scan" "50000|0|0|0|0|0" "$(fields bulk big hostB $NOW $CAP $RCAP 50000 fifty)"
echo "50 000 findings first scan took $(( ($(date +%s%N) - start_big) / 1000000 )) ms"
start_same="$(date +%s%N)"
check "the same 50 000 again rewrite nothing" "0|0|0|0|0|0" "$(fields bulk big hostB $((NOW + 1)) $CAP $RCAP 50000 fifty)"
echo "50 000 unchanged scan took $(( ($(date +%s%N) - start_same) / 1000000 )) ms"
start_swap="$(date +%s%N)"
check "hostB swaps to 50 000 other findings: 50 000 resolved, 50 000 inserted" "50000|0|50000|0|0|0" "$(fields bulk big hostB $((NOW + 2)) $CAP $RCAP 50000 swapped)"
echo "50 000 swap scan took $(( ($(date +%s%N) - start_swap) / 1000000 )) ms"
check "counter equals the real counts after the big scans" "$(real_counter big)" "$(counter big)"
check "per-asset counts equal the real counts after the big scans" 0 "$(asset_counters_equal)"

echo "--- one asset's resolved history is capped per asset and never makes a scan cost its history"
check "asset y stores 2" "2|0|0|0|0|0" "$(fields scan pa y $NOW $CAP $RCAP openssl/R1 curl/R2)"
check "asset y resolves them" "0|0|2|0|0|0" "$(fields scan pa y $((NOW + 1)) $CAP $RCAP)"
check "asset x first inventory" "5|0|0|0|0|0" "$(fields bulk pa x $NOW $CAP $RCAP 5 xa)"
check "asset x second inventory: 5 resolved, 2 over the asset cap of 3 evicted" "5|0|5|0|2|0" "$(VULN_ASSET_RESOLVED_CAP=3 fields bulk pa x $((NOW + 2)) $CAP $RCAP 5 xb)"
check "asset x keeps its 3 newest resolved rows" 3 "$(sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'pa' AND asset = 'x' AND resolved_micros IS NOT NULL")"
check "asset y history untouched by x churn" 2 "$(sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'pa' AND asset = 'y' AND resolved_micros IS NOT NULL")"
check "counters equal the real counts after the asset eviction" "$(real_counter pa)" "$(counter pa)"
check "per-asset counts equal the real counts after the asset eviction" 0 "$(asset_counters_equal)"
sql "INSERT INTO vuln_findings SELECT 'hist', 'hist', 'Debian:12', repeat('h', 100) || g, 'R1', '1.0', '1.2', 7.5, 0.5, false, g % 9000, 1, 1, 2 + g FROM generate_series(1, 1000000) g"
sql "INSERT INTO vuln_findings SELECT 'hist', 'seed' || (g % 100), 'Debian:12', repeat('p', 100) || g, 'R1', '1.0', '1.2', 7.5, 0.5, false, g % 9000, 1, 1, NULL FROM generate_series(1, 200000) g"
sql "ANALYZE vuln_findings"
echo "tenant hist: 1 000 000 resolved rows on asset hist (above the asset cap, seeded by SQL) and 200 000 open rows on 100 other assets"
check "first scan of the tenant bootstraps the counter from 1 200 000 rows" "1|0|0|0|0|0" "$(fields scan hist boot $NOW $CAP $RCAP openssl/R1)"
check "bootstrapped counter equals the real counts" "$(real_counter hist)" "$(counter hist)"
tuples() { sleep 2; sql "SELECT seq_tup_read + idx_tup_fetch FROM pg_stat_user_tables WHERE relname = 'vuln_findings'"; }
start_recount="$(date +%s%N)"
check "the first scan of a SQL-seeded asset recounts its resolved rows once" "0|0|0|0|0|0" "$(fields scan hist hist $((NOW - 1)) $CAP $RCAP)"
echo "recount of 1 000 000 resolved rows took $(( ($(date +%s%N) - start_recount) / 1000000 )) ms"
check "the asset count is 1 000 000" 1000000 "$(asset_counter hist hist)"
tuples_before="$(tuples)"
start_hist="$(date +%s%N)"
check "scan of hist, one finding" "1|0|0|0|0|0" "$(fields scan hist hist $NOW $CAP $RCAP openssl/R1)"
hist_ms=$(( ($(date +%s%N) - start_hist) / 1000000 ))
echo "one-finding scan of an asset with 1 000 000 resolved rows took $hist_ms ms"
tuples_after="$(tuples)"
echo "table rows read by that scan: $((tuples_after - tuples_before))"
check "that scan reads a handful of rows, not the asset history (limit 1000)" 1 "$(( tuples_after - tuples_before < 1000 ))"
start_hist="$(date +%s%N)"
check "the same finding again rewrites nothing" "0|0|0|0|0|0" "$(fields scan hist hist $((NOW + 1)) $CAP $RCAP openssl/R1)"
echo "unchanged one-finding scan of that asset took $(( ($(date +%s%N) - start_hist) / 1000000 )) ms"
vuln scan hist hist $((NOW + 2)) $CAP $RCAP openssl/R1 >"$work/hist.out" &
hist_pid=$!
check "another asset of the tenant scans while hist scans" "1|0|0|0|0|0" "$(fields scan hist other $NOW $CAP $RCAP openssl/R1)"
wait "$hist_pid"
check "counter equals the real counts for the history tenant" "$(real_counter hist)" "$(counter hist)"
check "per-asset counts equal the real counts at the end" 0 "$(asset_counters_equal)"

echo "--- an asset under its resolved cap reads no resolved-index row; a forged count heals on the next UTC day"
sql "INSERT INTO vuln_findings SELECT 'under', 'u1', 'Debian:12', 'upkg' || g, 'R1', '1.0', '1.2', 7.5, 0.5, false, 1, 1, 1, 2 + g FROM generate_series(1, 99999) g"
sql "INSERT INTO vuln_findings SELECT 'under', 'u1', 'Debian:12', 'live' || g, 'R1', '1.0', '1.2', 7.5, 0.5, false, 1, 1, 1, NULL FROM generate_series(1, 2) g"
check "first scan of u1 recounts its 99 999 resolved rows, resolves two, evicts one over the cap" "0|0|2|0|1|0" "$(fields scan under u1 $NOW $CAP $RCAP)"
check "count is the cap after that eviction" "100000" "$(asset_counter under u1)"
check "rows are the cap" "100000" "$(real_asset_counter under u1)"
sql "UPDATE vuln_asset_resolved SET resolved_total = 99999 WHERE tenant = 'under' AND asset = 'u1'"
sql "DELETE FROM vuln_findings WHERE ctid = ANY (ARRAY(SELECT ctid FROM vuln_findings WHERE tenant = 'under' AND asset = 'u1' AND resolved_micros IS NOT NULL LIMIT 1))"
check "count and rows agree on 99 999 again" "99999" "$(real_asset_counter under u1)"
check "u1 finds one open row" "1|0|0|0|0|0" "$(fields scan under u1 $((NOW + 1)) $CAP $RCAP one/R1)"
tuples_under_before="$(tuples)"
check "u1 resolves it again: count 100 000 is not over the cap" "0|0|1|0|0|0" "$(fields scan under u1 $((NOW + 2)) $CAP $RCAP)"
echo "table rows read by that scan under the cap: $(( $(tuples) - tuples_under_before ))"
check "an under-the-cap resolving scan reads a handful of rows (limit 1000, the walk would read 100 000)" 1 "$(( $(tuples) - tuples_under_before < 1000 ))"
check "count equals rows under the cap" "$(real_asset_counter under u1)" "$(asset_counter under u1)"
echo "a forged count (too low, too high) heals on the first scan of the next UTC day"
sql "UPDATE vuln_asset_resolved SET resolved_total = 1 WHERE tenant = 'under' AND asset = 'u1'"
check "forged-low count survives a scan of the same day" "0|0|0|0|0|0" "$(fields scan under u1 $((NOW + 3)) $CAP $RCAP)"
check "forged-low count is still 1" 1 "$(asset_counter under u1)"
check "next UTC day heals it" "0|0|0|0|0|0" "$(fields scan under u1 $((NOW + 86400000000)) $CAP $RCAP)"
check "healed count equals rows" "$(real_asset_counter under u1)" "$(asset_counter under u1)"
sql "UPDATE vuln_asset_resolved SET resolved_total = 5000000 WHERE tenant = 'under' AND asset = 'u1'"
check "forged-high count heals the next day" "0|0|0|0|0|0" "$(fields scan under u1 $((NOW + 2 * 86400000000)) $CAP $RCAP)"
check "healed again" "$(real_asset_counter under u1)" "$(asset_counter under u1)"
check "a negative count is refused by the table" "refused" "$(sql "UPDATE vuln_asset_resolved SET resolved_total = -1 WHERE tenant = 'under'" >/dev/null 2>&1 && echo stored || echo refused)"
echo "--- the per-asset table holds a row only while the asset has resolved rows"
for index in $(seq 1 200); do vuln scan ghost "g$index" $NOW $CAP $RCAP >/dev/null; done
check "200 empty scans of 200 assets leave no per-asset row" "0|0" "$(sql "SELECT count(*) || '|' || (SELECT count(*) FROM vuln_findings WHERE tenant = 'ghost') FROM vuln_asset_resolved WHERE tenant = 'ghost'")"
check "an asset that resolves a row gets one" "1|0|0|0|0|0" "$(fields scan ev e1 $NOW $CAP 1 a/R1)"
check "e1 resolves it" "0|0|1|0|0|0" "$(fields scan ev e1 $((NOW + 1)) $CAP 1)"
check "e1 has a row of 1" 1 "$(asset_counter ev e1)"
check "e2 stores one" "1|0|0|0|0|0" "$(fields scan ev e2 $((NOW + 2)) $CAP 1 b/R1)"
check "e2 resolves it, the tenant cap of 1 evicts the oldest (e1's)" "0|0|1|0|1|0" "$(fields scan ev e2 $((NOW + 3)) $CAP 1)"
check "the evicted asset's row is deleted, not left at 0" "-1" "$(asset_counter ev e1)"
check "e2 keeps its row" 1 "$(asset_counter ev e2)"
check "per-asset rows equal the real counts" 0 "$(asset_counters_equal)"
echo "--- a tenant without counters: the scan refuses and changes nothing, the rebuild is its own statement"
sql "INSERT INTO vuln_findings SELECT 'rb', 'r' || (g % 3), 'Debian:12', 'rpkg' || g, 'R1', '1.0', '1.2', 7.5, 0.5, false, 1, 1, 1, CASE WHEN g % 2 = 0 THEN 2 + g END FROM generate_series(1, 300) g"
check "scan function answers counters missing and writes nothing" "0|0|1|0|300" "$(sql "SELECT n_inserted || '|' || n_resolved || '|' || n_counters_missing || '|' || (SELECT count(*) FROM vuln_finding_rows WHERE tenant = 'rb') || '|' || (SELECT count(*) FROM vuln_findings WHERE tenant = 'rb') FROM vuln_scan_store('rb', 'r0', '[]'::jsonb, 1000, $NOW, 1000, 1, 100000)")"
check "rebuild builds the counters" 1 "$(sql "SELECT vuln_counters_rebuild('rb')")"
check "rebuild again does nothing" 0 "$(sql "SELECT vuln_counters_rebuild('rb')")"
check "tenant counter equals the real counts" "$(real_counter rb)" "$(counter rb)"
check "per-asset rows equal the real counts" 0 "$(asset_counters_equal)"
check "a scan now proceeds and resolves the 50 open rows of r0 it no longer lists" "1|0|50|0|0|0" "$(fields scan rb r0 $NOW $CAP $RCAP one/R1)"
echo "--- kev_since_micros is the first KEV time of a finding and is never cleared"
kev_state() { sql "SELECT kev || '|' || coalesce(kev_since_micros - $NOW, -1) FROM vuln_findings WHERE tenant = '$1' AND package = '$2'"; }
check "scan 1: curl is KEV, openssl is not" "2|0|0|0|0|0" "$(fields scan k h1 $NOW $CAP $RCAP curl/R1/kev openssl/R2)"
check "curl is KEV since the scan time" "true|0" "$(kev_state k curl)"
check "openssl has no KEV time" "false|-1" "$(kev_state k openssl)"
check "a rescan scored without the catalogue clears kev and updates the row" "0|1|0|0|0|0" "$(fields scan k h1 $((NOW + 1000)) $CAP $RCAP curl/R1 openssl/R2)"
check "kev is false, the KEV time is kept" "false|0" "$(kev_state k curl)"
check "flagged again later: kev true, first KEV time kept" "true|0" "$(fields scan k h1 $((NOW + 2000)) $CAP $RCAP curl/R1/kev openssl/R2 >/dev/null; kev_state k curl)"
check "openssl turns KEV at +3000" "0|1|0|0|0|0" "$(fields scan k h1 $((NOW + 3000)) $CAP $RCAP curl/R1/kev openssl/R2/kev)"
check "openssl KEV time is +3000" "true|3000" "$(kev_state k openssl)"
check "an empty scan resolves both" "0|0|2|0|0|0" "$(fields scan k h1 $((NOW + 4000)) $CAP $RCAP)"
check "seen again as KEV after the resolution: 2 reopened" "0|2|0|0|0|0" "$(fields scan k h1 $((NOW + 5000)) $CAP $RCAP curl/R1/kev openssl/R2/kev)"
check "an unchanged KEV rescan inside the granularity rewrites nothing" "0|0|0|0|0|0" "$(fields scan k h1 $((NOW + 5500)) $CAP $RCAP curl/R1/kev openssl/R2/kev)"
check "reopened curl keeps its first KEV time" "true|0" "$(kev_state k curl)"
check "reopened openssl keeps its first KEV time" "true|3000" "$(kev_state k openssl)"
fields scan k h1 $((NOW + 6000)) $CAP $RCAP >/dev/null
check "resolved then reopened without KEV: kev false, time kept" "false|0" "$(fields scan k h1 $((NOW + 7000)) $CAP $RCAP curl/R1 >/dev/null; kev_state k curl)"
check "a negative KEV time is refused by the table" "refused" "$(sql "UPDATE vuln_findings SET kev_since_micros = -1 WHERE tenant = 'k'" >/dev/null 2>&1 && echo stored || echo refused)"
check "both KEV indexes exist and hold no last_seen column" "2|0" "$(sql "SELECT count(*) || '|' || count(*) FILTER (WHERE indexdef LIKE '%last_seen%') FROM pg_indexes WHERE indexname IN ('vuln_findings_kev_open', 'vuln_findings_kev_resolved')")"
check "no index of vuln_findings holds last_seen_micros" 0 "$(sql "SELECT count(*) FROM pg_indexes WHERE tablename = 'vuln_findings' AND indexdef LIKE '%last_seen%'")"
check "recreated scan function keeps its search_path and planner pins" "search_path=pg_catalog, public, pg_temp,enable_seqscan=off,enable_bitmapscan=off,jit=off" "$(sql "SELECT array_to_string(proconfig, ',') FROM pg_proc WHERE proname = 'vuln_scan_store'")"
hot() { sleep 2; sql "SELECT n_tup_hot_upd FROM pg_stat_user_tables WHERE relname = 'vuln_findings'"; }
check "hot tenant: 3 rows, one KEV" "3|0|0|0|0|0" "$(fields scan hot h1 $NOW $CAP $RCAP a/R1/kev b/R2 c/R3)"
hot_before="$(hot)"
check "an hour later the 3 rows only move their last seen" "0|3|0|0|0|0" "$(fields scan hot h1 $((NOW + HOUR + 1)) $CAP $RCAP a/R1/kev b/R2 c/R3)"
hot_after="$(hot)"
echo "n_tup_hot_upd grew by $((hot_after - hot_before))"
check "the 3 refreshed rows are all HOT updates (no index holds last_seen_micros)" 3 "$((hot_after - hot_before))"
sql "VACUUM vuln_findings"
sql "INSERT INTO vuln_findings SELECT 'kevidx', 'a' || (g % 7), 'Debian:12', 'kp' || g, 'R1', '1.0', '1.2', 7.5, 0.5, g % 5 = 0, 1, g, g, CASE WHEN g % 3 = 0 THEN g + 10 END, CASE WHEN g % 5 = 0 THEN g END FROM generate_series(1, 30000) g"
sql "VACUUM ANALYZE vuln_findings"
planner="SET enable_seqscan = off; SET enable_bitmapscan = off;"
check "open KEV count of a tenant reads vuln_findings_kev_open" "Index Only Scan using vuln_findings_kev_open" "$(sql "$planner EXPLAIN SELECT first_seen_micros, asset FROM vuln_findings WHERE tenant = 'kevidx' AND kev_since_micros IS NOT NULL AND resolved_micros IS NULL" | grep -o 'Index Only Scan using vuln_findings_kev_open' | head -1)"
check "resolved KEV in a window reads vuln_findings_kev_resolved" "Index Only Scan using vuln_findings_kev_resolved" "$(sql "$planner EXPLAIN SELECT first_seen_micros, asset FROM vuln_findings WHERE tenant = 'kevidx' AND kev_since_micros IS NOT NULL AND resolved_micros IS NOT NULL AND resolved_micros >= 100 AND resolved_micros < 20000" | grep -o 'Index Only Scan using vuln_findings_kev_resolved' | head -1)"
sql "$planner EXPLAIN SELECT first_seen_micros, asset FROM vuln_findings WHERE tenant = 'kevidx' AND kev_since_micros IS NOT NULL AND resolved_micros IS NULL"
sql "$planner EXPLAIN SELECT first_seen_micros, asset FROM vuln_findings WHERE tenant = 'kevidx' AND kev_since_micros IS NOT NULL AND resolved_micros IS NOT NULL AND resolved_micros >= 100 AND resolved_micros < 20000"

echo "--- vuln_0005 on a populated store: 2 000 000 open and 1 000 000 resolved rows of one tenant, 300 000 KEV"
for number in 1 2 3 4; do sql_old --single-transaction -f "/tmp/vuln-migrations/vuln_000$number.sql" >/dev/null; done
sql_old -c "INSERT INTO vuln_findings SELECT 'cap', 'cap' || (g % 1000), 'Debian:12', 'cp' || g, 'R1', '1.0', '1.2', 7.5, 0.5, g % 10 = 0, 1000 + g % 50, 1000 + g, 2000 + g, CASE WHEN g > 2000000 THEN 3000 + g END FROM generate_series(1, 3000000) g" >/dev/null
sql_old -c "ANALYZE vuln_findings" >/dev/null
check "seeded rows" "3000000|1000000|300000" "$(sql_old -c "SELECT count(*) || '|' || count(*) FILTER (WHERE resolved_micros IS NOT NULL) || '|' || count(*) FILTER (WHERE kev) FROM vuln_findings")"
start_migration="$(date +%s%N)"
sql_old --single-transaction -f /tmp/vuln-migrations/vuln_0005.sql >/dev/null
migration_ms=$(( ($(date +%s%N) - start_migration) / 1000000 ))
echo "vuln_0005 on 3 000 000 rows: ${migration_ms} ms in one transaction, which takes ACCESS EXCLUSIVE on the three tables first and holds it to the commit, so the lock time is that duration"
check "backfill counted: every KEV row has its first_seen as KEV time, no other row has one" "300000|300000|0|0" "$(sql_old -c "SELECT count(*) FILTER (WHERE kev) || '|' || count(*) FILTER (WHERE kev_since_micros IS NOT NULL) || '|' || count(*) FILTER (WHERE kev AND kev_since_micros IS DISTINCT FROM first_seen_micros) || '|' || count(*) FILTER (WHERE NOT kev AND kev_since_micros IS NOT NULL) FROM vuln_findings")"
check "migrated store: function keeps its pins" "search_path=pg_catalog, public, pg_temp,enable_seqscan=off,enable_bitmapscan=off,jit=off" "$(sql_old -c "SELECT array_to_string(proconfig, ',') FROM pg_proc WHERE proname = 'vuln_scan_store'")"
check "migrated store: both indexes are valid" "2" "$(sql_old -c "SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname IN ('vuln_findings_kev_open', 'vuln_findings_kev_resolved') AND i.indisvalid")"
echo "failures=$failures"
exit "$failures"
REMOTE
