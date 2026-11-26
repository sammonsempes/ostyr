#!/usr/bin/env bash
# Usage: crates/vuln-match/tests/service-live.sh <lab-state-dir> <feeds-dir>
# Live check of ostyr-vuln on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the musl binary runs on the client VM against a scratch
# database of the datastore VM and psql reads the state back: findings and one KEV alert from a real OSV Debian slice, an upgraded package that resolves its
# finding, a deleted inventory file that resolves nothing, the hostile inventory files, a corrupt and a bomb archive, the empty feeds, a record with 1 676
# aliases, 10 001 inventory files, a stop in the middle of a round and a stop during the start, and SIGTERM exiting 0.
# <feeds-dir> holds slice.zip (a slice of the OSV Debian archive with KEV overlap, DLA-4008-1 included), bomb.zip, kev.json and epss.csv.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: service-live.sh <lab-state-dir> <feeds-dir>}"
feeds="${2:?usage: service-live.sh <lab-state-dir> <feeds-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
binary="$here/target/x86_64-unknown-linux-musl/release/ostyr-vuln"
[[ -x "$binary" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p vuln-match --bin ostyr-vuln" >&2; exit 2; }
for name in slice.zip bomb.zip kev.json epss.csv; do [[ -f "$feeds/$name" ]] || { echo "missing $feeds/$name" >&2; exit 2; }; done

database="vuln_svc_$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
datastore_ssh "sudo -u postgres createdb -O '$owner' '${database}_start'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database; sudo -u postgres dropdb --if-exists ${database}_start" || true' EXIT

target="$client_user@$client_address"
ssh "${ssh_options[@]}" "$target" "rm -rf /tmp/vuln-feeds && mkdir /tmp/vuln-feeds"
scp "${ssh_options[@]}" "$binary" "$target:/tmp/ostyr-vuln"
scp "${ssh_options[@]}" "$feeds/slice.zip" "$feeds/bomb.zip" "$feeds/kev.json" "$feeds/epss.csv" "$target:/tmp/vuln-feeds/"
ssh "${ssh_options[@]}" "$target" "DATABASE=$database START_DATABASE=${database}_start bash -s" <<'REMOTE'
set -euo pipefail
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
work="$(mktemp -d)"
service_pid=""
cleanup() { [[ -n "$service_pid" ]] && kill "$service_pid" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
mkdir -p "$work/inventory" "$work/stage"
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
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
slice_sha="$(sha256sum /tmp/vuln-feeds/slice.zip | cut -d' ' -f1)"
bomb_sha="$(sha256sum /tmp/vuln-feeds/bomb.zip | cut -d' ' -f1)"
cp /tmp/vuln-feeds/slice.zip "$work/osv.zip"
cp /tmp/vuln-feeds/kev.json "$work/kev.json"
cp /tmp/vuln-feeds/epss.csv "$work/epss.csv"
write_settings() {
    local prefixes='    "": CC-BY-4.0'
    [[ "${2:-}" == "no-prefixes" ]] && prefixes='    "NOSUCH-": CC-BY-4.0'
    cat >"$work/service.yaml" <<YAML
tenant: acme
pg_settings: $work/pg.yaml
audit_file: $work/audit.log
inventory_dir: $work/inventory
osv_archive: $work/osv.zip
kev_file: $work/kev.json
epss_file: $work/epss.csv
round_seconds: 10
feed:
  sha256: $1
  prefix_licences:
$prefixes
  allowed_licences: [CC-BY-4.0]
YAML
}
package_json() { printf '[{"ecosystem":"Debian:12","name":"%s","version":"%s"},{"ecosystem":"Debian:12","name":"bash","version":"5.2.15-2"}]' "$1" "$2"; }
put() { printf '%s' "$2" >"$work/stage/$1.json"; mv "$work/stage/$1.json" "$work/inventory/$1.json"; }
rounds() { grep -c "round done" "$work/service.log" || true; }
wait_rounds() {
    local target="$1" attempt
    for attempt in $(seq 1 180); do
        [[ "$(rounds)" -ge "$target" ]] && return 0
        sleep 1
    done
    echo "FAIL: $target rounds never completed"; cat "$work/service.log"; exit 1
}
open_of() { sql "SELECT coalesce(string_agg(package || ' ' || record_id, ',' ORDER BY package, record_id), '') FROM vuln_findings WHERE tenant = 'acme' AND asset = '$1' AND resolved_micros IS NULL"; }
count_of() { sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'acme' AND asset = '$1' AND resolved_micros IS NULL"; }

write_settings "$slice_sha"
put web-1 "$(package_json openssl 1.0.1e-1)"
put web-2 "$(package_json exim4 4.69-1)"
/tmp/ostyr-vuln "$work/service.yaml" 2>"$work/service.log" &
service_pid=$!
wait_rounds 1
echo "--- round 1"
check "web-1 open findings include Heartbleed" "openssl DEBIAN-CVE-2014-0160" "$(open_of web-1 | tr ',' '\n' | grep -x 'openssl DEBIAN-CVE-2014-0160')"
check "web-2 has exim4 findings" "1" "$(( $(count_of web-2) > 0 ? 1 : 0 ))"
check "KEV alert for Heartbleed on web-1" "1" "$(sql "SELECT count(*) FROM alerts WHERE tenant = 'acme' AND rule_id = 'vuln.kev' AND rule_title LIKE '%CVE-2014-0160%' AND event_ids::text LIKE '%web-1%'")"
check "web-1 finding is flagged kev" "t" "$(sql "SELECT kev FROM vuln_findings WHERE tenant = 'acme' AND asset = 'web-1' AND record_id = 'DEBIAN-CVE-2014-0160'")"
check "only tenant acme holds rows" "acme" "$(sql "SELECT string_agg(DISTINCT tenant, ',') FROM vuln_findings")"
web2_before="$(open_of web-2)"
echo "--- an upgraded package resolves its finding on the next round"
put web-1 "$(package_json openssl 1.0.1g-1)"
wait_rounds 2
check "Heartbleed resolved on web-1" "0" "$(sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'acme' AND asset = 'web-1' AND record_id = 'DEBIAN-CVE-2014-0160' AND resolved_micros IS NULL")"
check "Heartbleed row kept as resolved" "1" "$(sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'acme' AND asset = 'web-1' AND record_id = 'DEBIAN-CVE-2014-0160' AND resolved_micros IS NOT NULL")"
echo "--- a deleted inventory file resolves nothing"
rm "$work/inventory/web-2.json"
wait_rounds 4
check "web-2 findings unchanged after its file is deleted" "$web2_before" "$(open_of web-2)"
echo "--- hostile inventory files, each refused alone"
before_rounds="$(rounds)"
seq 1 1000000 | sed 's/.*/{"ecosystem":"Debian:12","name":"a","version":"1"},/' | { printf '['; cat; printf '{"ecosystem":"Debian:12","name":"a","version":"1"}]'; } >"$work/inventory/million.json"
seq 1 1000000 | sed 's/.*/1,/' | { printf '['; cat; printf '1]'; } >"$work/inventory/ints.json"
truncate -s 1G "$work/inventory/sparse.json"
ln -s /etc/shadow "$work/inventory/shadow.json"
mkfifo "$work/inventory/pipe.json"
head -c 200000 /dev/zero | tr '\0' '[' >"$work/inventory/nested.json"
for name in '-x' 'a b' 'h'$'\xc3\xa9''llo' '.' '.hidden' 'a;id'; do printf '%s' "$(package_json openssl 1.0.1e-1)" >"$work/inventory/$name.json"; done
put web-3 "$(package_json openssl 1.0.1e-1)"
wait_rounds "$((before_rounds + 2))"
check "hostile files left only grammar-valid assets (a;id is valid) with findings" "a;id,web-1,web-2,web-3" "$(sql "SELECT string_agg(DISTINCT asset, ',' ORDER BY asset) FROM vuln_findings WHERE tenant = 'acme'")"
check "the service still runs" "1" "$(kill -0 "$service_pid" && echo 1)"
grep "round done" "$work/service.log" | tail -1
grep -E "inventory (file|entry) refused" "$work/service.log" | sed 's/^[^ ]* //' | sort -u | head -20
rm -f "$work/inventory/million.json" "$work/inventory/ints.json" "$work/inventory/sparse.json" "$work/inventory/shadow.json" "$work/inventory/pipe.json" "$work/inventory/nested.json"
find "$work/inventory" -name '*.json' ! -name 'web-*' -delete
echo "--- a corrupt archive (cut inside its size, the pinned sha no longer matches): the previous set stays, nothing is resolved"
web1_open="$(open_of web-1)"
web3_open="$(open_of web-3)"
archive_size="$(stat -c %s "$work/osv.zip")"
head -c "$((archive_size / 2))" "$work/osv.zip" >"$work/osv.partial" && mv "$work/osv.partial" "$work/osv.zip"
check "the archive was really cut" "1" "$(( $(stat -c %s "$work/osv.zip") < archive_size ? 1 : 0 ))"
before_rounds="$(rounds)"
wait_rounds "$((before_rounds + 2))"
check "web-3 findings kept under a corrupt archive" "$web3_open" "$(open_of web-3)"
check "web-1 findings kept under a corrupt archive" "$web1_open" "$(open_of web-1)"
check "the degraded feed is named" "1" "$(( $(grep -c 'feed not loaded, keeping the previous set' "$work/service.log") > 0 ? 1 : 0 ))"
check "the round line says degraded=1" "1" "$(grep 'round done' "$work/service.log" | tail -1 | grep -c 'degraded=1')"
cp /tmp/vuln-feeds/bomb.zip "$work/osv.zip"
write_settings "$bomb_sha"
kill -HUP "$service_pid"
before_rounds="$(rounds)"
wait_rounds "$((before_rounds + 2))"
check "web-3 findings kept under a bomb archive" "$web3_open" "$(open_of web-3)"
grep "feed not loaded" "$work/service.log" | sed 's/^[^ ]* //' | sort -u
check "the reload was audited under tenant all" "1" "$(( $(grep -c '"tenant":"all"' "$work/audit.log") > 0 ? 1 : 0 ))"
echo "--- empty feeds are refused, nothing is resolved"
cp /tmp/vuln-feeds/slice.zip "$work/osv.zip"
write_settings "$slice_sha" no-prefixes
kill -HUP "$service_pid"
before_rounds="$(rounds)"
wait_rounds "$((before_rounds + 2))"
check "removing prefix_licences leaves web-1 findings" "$web1_open" "$(open_of web-1)"
check "removing prefix_licences leaves web-3 findings" "$web3_open" "$(open_of web-3)"
check "the empty OSV set is named" "1" "$(( $(grep -c 'the osv feed holds no usable entry' "$work/service.log") > 0 ? 1 : 0 ))"
check "the round line says degraded=1 (prefix_licences removed)" "1" "$(grep 'round done' "$work/service.log" | tail -1 | grep -c 'degraded=1')"
python3 -I -c "import zipfile; zipfile.ZipFile('$work/empty.zip', 'w').close()"
write_settings "$(sha256sum "$work/empty.zip" | cut -d' ' -f1)"
cp "$work/empty.zip" "$work/osv.zip"
kill -HUP "$service_pid"
before_rounds="$(rounds)"
wait_rounds "$((before_rounds + 2))"
check "a valid empty zip leaves web-1 findings" "$web1_open" "$(open_of web-1)"
check "a valid empty zip leaves web-3 findings" "$web3_open" "$(open_of web-3)"
cp /tmp/vuln-feeds/slice.zip "$work/osv.zip"
write_settings "$slice_sha"
printf '{"vulnerabilities":[]}' >"$work/kev.json"
printf '#model_version:v1,score_date:2026-01-01T00:00:00Z\ncve,epss,percentile\n' >"$work/epss.csv"
kev_lines="$(grep -c 'the kev feed holds no usable entry' "$work/service.log" || true)"
before_rounds="$(rounds)"
wait_rounds "$((before_rounds + 2))"
check "an empty KEV file leaves web-1 findings" "$web1_open" "$(open_of web-1)"
check "an empty KEV and EPSS file are named" "1" "$(( $(grep -c 'the kev feed holds no usable entry' "$work/service.log") > kev_lines && $(grep -c 'the epss feed holds no usable entry' "$work/service.log") > 0 ? 1 : 0 ))"
check "the round line says degraded=2" "1" "$(grep 'round done' "$work/service.log" | tail -1 | grep -c 'degraded=2')"
cp /tmp/vuln-feeds/kev.json "$work/kev.json"
cp /tmp/vuln-feeds/epss.csv "$work/epss.csv"
echo "--- DLA-4008-1 (1 676 aliases) on a linux-6.1 asset: a finding with a cut alias list, alerts for the stored finding"
put k-1 '[{"ecosystem":"Debian:11","name":"linux-6.1","version":"6.1.0-1"}]'
before_rounds="$(rounds)"
wait_rounds "$((before_rounds + 2))"
check "k-1 holds the DLA-4008-1 finding" "1" "$(sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'acme' AND asset = 'k-1' AND record_id = 'DLA-4008-1' AND resolved_micros IS NULL")"
check "k-1 stored the omitted alias count (838 CVE aliases, 100 kept)" "738" "$(sql "SELECT aliases_omitted FROM vuln_findings WHERE tenant = 'acme' AND asset = 'k-1' AND record_id = 'DLA-4008-1'")"
check "k-1 raised its two KEV alerts" "2" "$(sql "SELECT count(*) FROM alerts WHERE tenant = 'acme' AND rule_id = 'vuln.kev' AND event_ids::text LIKE '%k-1%'")"
echo "--- 10 001 inventory files: sorted then cut, the first asset left out is named"
mkdir -p "$work/bulk"
seq 0 10000 | while read -r number; do printf '[]' >"$work/bulk/$(printf 'bulk-%05d' "$number").json"; done
mv "$work/bulk"/*.json "$work/inventory/"
before_rounds="$(rounds)"
wait_rounds "$((before_rounds + 1))"
sleep 2
over_line="$(grep 'round incomplete' "$work/service.log" | grep ' left_out=[1-9]' | tail -1)"
echo "$over_line"
left_count="$(find "$work/inventory" -name '*.json' | wc -l)"
check "left_out counts the files over the cap" "$((left_count - 10000))" "$(sed -n 's/.* left_out=\([0-9]*\) .*/\1/p' <<<"$over_line")"
expected_first="$(find "$work/inventory" -name '*.json' -printf '%f\n' | sed 's/\.json$//' | LC_ALL=C sort | sed -n '10001p')"
check "the first asset left out is named" "\"$expected_first\"" "$(sed -n 's/.*first_left_out=\("[^"]*"\).*/\1/p' <<<"$over_line")"
check "the assets left out were not resolved" "$web1_open" "$(open_of web-1)"
echo "--- a stop in the middle of a round: the asset in flight finishes, the round names the stop, exit 0"
rm -f "$work/inventory"/bulk-*.json
seq 0 6000 | while read -r number; do printf '[]' >"$work/bulk/$(printf 'bulk-%05d' "$number").json"; done
mv "$work/bulk"/*.json "$work/inventory/"
in_round() { sql "SELECT count(*) FROM pg_stat_activity WHERE datname = '$DATABASE' AND pid <> pg_backend_pid() AND state <> 'idle in transaction (aborted)'"; }
for attempt in $(seq 1 1200); do
    [[ "$(in_round)" -gt 0 ]] && break
    sleep 0.1
done
check "a round is in progress when the stop arrives" "1" "$(( $(in_round) > 0 ? 1 : 0 ))"
kill -TERM "$service_pid"
set +e
wait "$service_pid"
exit_code=$?
set -e
service_pid=""
check "a stop in the middle exits 0" "0" "$exit_code"
check "the stop is named in the round line" "1" "$(( $(grep -c 'round incomplete.*stopped=true' "$work/service.log") > 0 ? 1 : 0 ))"
grep 'round incomplete' "$work/service.log" | tail -2
check "no scan failed" "0" "$(grep -c 'the asset scan failed' "$work/service.log" || true)"
echo "--- a stop during the start is named"
rm -f "$work/inventory"/bulk-*.json
sed "s/database: $DATABASE/database: $START_DATABASE/" "$work/pg.yaml" >"$work/pg-start.yaml"
sed "s#$work/pg.yaml#$work/pg-start.yaml#" "$work/service.yaml" >"$work/service-start.yaml"
named=""
for delay in 0.0 0.01 0.02 0.03 0.05 0.08 0.12 0.2 0.3 0.5; do
    sql_start() { psql -X -q -tA -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$START_DATABASE" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public" >/dev/null; }
    sql_start
    /tmp/ostyr-vuln "$work/service-start.yaml" 2>"$work/start.log" &
    start_pid=$!
    sleep "$delay"
    kill -TERM "$start_pid" 2>/dev/null || true
    set +e
    wait "$start_pid"
    start_exit=$?
    set -e
    if grep -q 'a stop arrived before the first round' "$work/start.log"; then named="$delay"; break; fi
done
check "a stop during the start is named (delay $named) and exits 0" "0" "$start_exit"
check "the stop during the start was observed" "1" "$([[ -n "$named" ]] && echo 1 || echo 0)"
check "no round ran under a stop during the start" "0" "$(grep -c 'round done' "$work/start.log" || true)"
exit "$failures"
REMOTE
