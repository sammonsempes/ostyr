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
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true' EXIT

scp "${ssh_options[@]}" "$binary" "$client_user@$client_address:/tmp/vuln_store"
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
vuln() { /tmp/vuln_store "$work/pg.yaml" "$@"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
open_rows() { sql "SELECT count(*) FROM vuln_findings WHERE tenant = '$1' AND resolved_micros IS NULL"; }
all_rows() { sql "SELECT count(*) FROM vuln_findings WHERE tenant = '$1'"; }
counter() { sql "SELECT coalesce((SELECT total FROM vuln_finding_rows WHERE tenant = '$1'), -1)"; }
fields() { vuln "$@" | sed -E 's/ScanOutcome \{ inserted: ([0-9]+), updated: ([0-9]+), resolved: ([0-9]+), refused_no_room: ([0-9]+), refused: ([0-9]+) \}/\1|\2|\3|\4|\5/'; }
NOW=1700000000000000
CAP=2000000

vuln migrate
check "migration applied: function and tables exist" "1|1|1" "$(sql "SELECT (SELECT count(*) FROM pg_proc WHERE proname = 'vuln_scan_store') || '|' || count(*) || '|' || (SELECT count(*) FROM pg_class WHERE relname = 'vuln_finding_rows') FROM pg_class WHERE relname = 'vuln_findings'")"

check "scan 1 of h1 stores 3: inserted|updated|resolved|no_room|refused" "3|0|0|0|0" "$(fields scan a h1 $NOW $CAP openssl/R1 curl/R2 zlib/R3)"
check "tenant a open rows" 3 "$(open_rows a)"
first_seen="$(sql "SELECT first_seen_micros FROM vuln_findings WHERE tenant = 'a' AND package = 'curl'")"
check "scan 2 without zlib resolves it" "0|2|1|0|0" "$(fields scan a h1 $((NOW + 1000)) $CAP openssl/R1 curl/R2)"
echo "psql read-back:"
sql "SELECT package, first_seen_micros - $NOW, last_seen_micros - $NOW, coalesce(resolved_micros - $NOW, -1) FROM vuln_findings WHERE tenant = 'a' ORDER BY package"
check "zlib resolved at scan 2" "1000" "$(sql "SELECT resolved_micros - $NOW FROM vuln_findings WHERE tenant = 'a' AND package = 'zlib'")"
check "curl first seen kept, last seen moved" "$first_seen|$((NOW + 1000))" "$(sql "SELECT first_seen_micros || '|' || last_seen_micros FROM vuln_findings WHERE tenant = 'a' AND package = 'curl'")"
check "open rows after scan 2" 2 "$(open_rows a)"
check "zlib seen again clears the resolution" "0|3|0|0|0" "$(fields scan a h1 $((NOW + 2000)) $CAP zlib/R3 openssl/R1 curl/R2)"
check "all three open again" 3 "$(open_rows a)"
check "scan of h1 with only zlib resolves the others" "0|1|2|0|0" "$(fields scan a h1 $((NOW + 3000)) $CAP zlib/R3)"
check "other asset unaffected: h2 scan of a" "1|0|0|0|0" "$(fields scan a h2 $NOW $CAP openssl/R1)"
check "h1 scan does not resolve h2" 1 "$(sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'a' AND asset = 'h2' AND resolved_micros IS NULL")"

check "tenant b starts empty" 0 "$(all_rows b)"
before_a="$(sql "SELECT md5(string_agg(t::text, ',' ORDER BY package, asset)) FROM vuln_findings t WHERE tenant = 'a'")"
check "tenant b scan of the same keys inserts" "2|0|0|0|0" "$(fields scan b h1 $NOW $CAP openssl/R1 curl/R2)"
check "tenant a rows untouched by tenant b" "$before_a" "$(sql "SELECT md5(string_agg(t::text, ',' ORDER BY package, asset)) FROM vuln_findings t WHERE tenant = 'a'")"
fields scan a h1 $((NOW + 4000)) $CAP >/dev/null
check "tenant a empty scan leaves tenant b open" 2 "$(open_rows b)"

echo "--- cap at commit, two assets of one tenant at cap minus one"
check "seed 9 of cap 10" "9|0|0|0|0" "$(fields bulk c s0 $NOW 10 9 seed)"
fields bulk c x1 $NOW 10 5 xa >"$work/x.out" &
first=$!
fields bulk c y1 $NOW 10 5 ya >"$work/y.out" &
second=$!
wait "$first" "$second"
check "rows exactly at the cap" 10 "$(all_rows c)"
check "counter at the cap" 10 "$(counter c)"
check "inserted of the two scans sum to 1" 1 "$(cat "$work/x.out" "$work/y.out" | awk -F'|' '{s += $1} END {print s}')"
check "refused_no_room of the two scans sum to 9" 9 "$(cat "$work/x.out" "$work/y.out" | awk -F'|' '{s += $4} END {print s}')"
check "a full tenant does not block another tenant" "5|0|0|0|0" "$(fields bulk d s0 $NOW 10 5 other)"
check "update and resolve still work at the cap" "0|9|0|0|0" "$(fields bulk c s0 $((NOW + 1)) 10 9 seed)"
check "a scan of a full tenant refuses only new rows" "0|0|0|3|0" "$(fields bulk c z1 $NOW 10 3 zz)"
check "counter still equals rows for every tenant" 0 "$(sql "SELECT count(*) FROM (SELECT tenant, count(*) AS n FROM vuln_findings GROUP BY tenant) c JOIN vuln_finding_rows r USING (tenant) WHERE r.total <> c.n")"

echo "--- six concurrent scans of one asset"
for letter in a b c d e f; do
    fields bulk e h1 $((NOW + 10)) $CAP 50 "p$letter" >"$work/e-$letter.out" &
done
wait
check "one scan is the full truth: 50 open rows" 50 "$(open_rows e)"
check "the open rows all come from one scan" 1 "$(sql "SELECT count(DISTINCT substring(package from '^[a-z]+')) FROM vuln_findings WHERE tenant = 'e' AND resolved_micros IS NULL")"
check "counter equals rows" "$(all_rows e)" "$(counter e)"

echo "--- paging and refusals"
check "bulk 1200 stored" "1200|0|0|0|0" "$(fields bulk p h1 $NOW $CAP 1200 pkg)"
check "limit 500 pages through 1200 rows" "pages=3 rows=1200" "$(vuln pages p 500)"
long="$(printf 'k%.0s' $(seq 1 128))"
long_package="$(printf 'q%.0s' $(seq 1 127))"
check "longest keys stored" "2|0|0|0|0" "$(fields scan l "$long" $NOW $CAP "$long_package"1/"$long" "$long_package"2/"$long")"
check "longest cursor pages on" "pages=2 rows=2" "$(vuln pages l 1)"
check "ESC in a package is refused alone" "1|0|0|0|1" "$(fields scan m h1 $NOW $CAP $'bad\033pkg/R1' good/R2)"
check "only the good one is stored" 1 "$(all_rows m)"
check "50 001 findings refused before any I/O" "refused" "$(vuln bulk n h1 $NOW $CAP 50001 big >/dev/null 2>&1 && echo stored || echo refused)"
check "nothing stored for the refused scan" "0|-1" "$(all_rows n)|$(counter n)"
check "a cap of 0 is refused" "refused" "$(vuln scan n h1 $NOW 0 a/R1 >/dev/null 2>&1 && echo stored || echo refused)"
echo "failures=$failures"
exit "$failures"
REMOTE
