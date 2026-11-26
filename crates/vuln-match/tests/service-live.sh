#!/usr/bin/env bash
# Usage: crates/vuln-match/tests/service-live.sh <lab-state-dir> <feeds-dir>
# Live check of ostyr-vuln on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the musl binary runs on the client VM against a scratch
# database of the datastore VM and psql reads the state back: findings and one KEV alert from a real OSV Debian slice, an upgraded package that resolves its
# finding, a deleted inventory file that resolves nothing, the hostile inventory files, a corrupt and a bomb archive, and SIGTERM exiting 0.
# <feeds-dir> holds slice.zip (a slice of the OSV Debian archive with KEV overlap), bomb.zip, kev.json and epss.csv.
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
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true' EXIT

target="$client_user@$client_address"
ssh "${ssh_options[@]}" "$target" "rm -rf /tmp/vuln-feeds && mkdir /tmp/vuln-feeds"
scp "${ssh_options[@]}" "$binary" "$target:/tmp/ostyr-vuln"
scp "${ssh_options[@]}" "$feeds/slice.zip" "$feeds/bomb.zip" "$feeds/kev.json" "$feeds/epss.csv" "$target:/tmp/vuln-feeds/"
ssh "${ssh_options[@]}" "$target" "DATABASE=$database bash -s" <<'REMOTE'
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
write_settings() {
    cat >"$work/service.yaml" <<YAML
tenant: acme
pg_settings: $work/pg.yaml
audit_file: $work/audit.log
inventory_dir: $work/inventory
osv_archive: $work/osv.zip
kev_file: /tmp/vuln-feeds/kev.json
epss_file: /tmp/vuln-feeds/epss.csv
round_seconds: 10
feed:
  sha256: $1
  prefix_licences:
    "": CC-BY-4.0
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
echo "--- a corrupt, then a bomb archive: the previous set stays, nothing is resolved"
web1_open="$(open_of web-1)"
web3_open="$(open_of web-3)"
head -c 100000 "$work/osv.zip" >"$work/osv.partial" && mv "$work/osv.partial" "$work/osv.zip"
before_rounds="$(rounds)"
wait_rounds "$((before_rounds + 2))"
check "web-3 findings kept under a corrupt archive" "$web3_open" "$(open_of web-3)"
check "web-1 findings kept under a corrupt archive" "$web1_open" "$(open_of web-1)"
check "the degraded feed is named" "1" "$(( $(grep -c 'feed not loaded, keeping the previous set' "$work/service.log") > 0 ? 1 : 0 ))"
cp /tmp/vuln-feeds/bomb.zip "$work/osv.zip"
write_settings "$bomb_sha"
kill -HUP "$service_pid"
before_rounds="$(rounds)"
wait_rounds "$((before_rounds + 2))"
check "web-3 findings kept under a bomb archive" "$web3_open" "$(open_of web-3)"
grep "feed not loaded" "$work/service.log" | sed 's/^[^ ]* //' | sort -u
check "the reload was audited under tenant all" "1" "$(( $(grep -c '"tenant":"all"' "$work/audit.log") > 0 ? 1 : 0 ))"
echo "--- SIGTERM"
kill -TERM "$service_pid"
set +e
wait "$service_pid"
exit_code=$?
set -e
service_pid=""
check "SIGTERM exits 0" "0" "$exit_code"
exit "$failures"
REMOTE
