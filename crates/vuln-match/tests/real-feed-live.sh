#!/usr/bin/env bash
# Usage: crates/vuln-match/tests/real-feed-live.sh <lab-state-dir> <feeds-dir> [ecosystems]
# Live check of ostyr-vuln on the REAL OSV Debian all.zip (T914C) on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the musl binary runs on
# the client VM with `feed.ecosystems` (default `Debian:12`), peak RSS is read from /usr/bin/time, a real package inventory is matched and the findings are
# read back by psql. <feeds-dir> holds all.zip (the Debian archive), kev.json and epss.csv. `UNFILTERED=1` runs without the selection: the archive is then
# refused loudly by the retained cap. `ROUNDS` (default 3) rounds are waited for, so the peak RSS covers the reload while the previous record set is alive;
# `ARCHIVE` names another archive in <feeds-dir> (the hostile one).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: real-feed-live.sh <lab-state-dir> <feeds-dir> [ecosystems]}"
feeds="${2:?usage: real-feed-live.sh <lab-state-dir> <feeds-dir> [ecosystems]}"
ecosystems="${3:-Debian:12}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
binary="$here/target/x86_64-unknown-linux-musl/release/ostyr-vuln"
[[ -x "$binary" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p vuln-match --bin ostyr-vuln" >&2; exit 2; }
for name in "${ARCHIVE:-all.zip}" kev.json epss.csv; do [[ -f "$feeds/$name" ]] || { echo "missing $feeds/$name" >&2; exit 2; }; done

database="vuln_real_$$"
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo awk -F= '\$1 == \"POSTGRES_USER\" {print \$2}' /etc/ostyr-lab/datastore.env")"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists $database" || true' EXIT

target="$client_user@$client_address"
ssh "${ssh_options[@]}" "$target" "rm -rf /tmp/vuln-real && mkdir /tmp/vuln-real"
scp "${ssh_options[@]}" "$binary" "$target:/tmp/ostyr-vuln"
scp "${ssh_options[@]}" "$feeds/${ARCHIVE:-all.zip}" "$feeds/kev.json" "$feeds/epss.csv" "$target:/tmp/vuln-real/"
ssh "${ssh_options[@]}" "$target" "DATABASE=$database ECOSYSTEMS='$ecosystems' ROUNDS='${ROUNDS:-3}' ARCHIVE='${ARCHIVE:-all.zip}' UNFILTERED='${UNFILTERED:-}' bash -s" <<'REMOTE'
set -euo pipefail
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
work="$(mktemp -d)"
service_pid=""
cleanup() { [[ -n "$service_pid" ]] && kill "$service_pid" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
mkdir -p "$work/inventory"
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
cp "/tmp/vuln-real/$ARCHIVE" "$work/osv.zip"
cp /tmp/vuln-real/kev.json "$work/kev.json"
cp /tmp/vuln-real/epss.csv "$work/epss.csv"
sha="$(sha256sum "$work/osv.zip" | cut -d' ' -f1)"
selection=""
if [[ -z "$UNFILTERED" ]]; then
    selection="  ecosystems: [$(printf '%s' "$ECOSYSTEMS" | sed 's/ /, /g')]"
fi
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
  sha256: $sha
  prefix_licences:
    "": CC-BY-4.0
  allowed_licences: [CC-BY-4.0]
$selection
YAML
printf '%s' '[{"ecosystem":"Debian:12","name":"openssl","version":"3.0.9-1"},{"ecosystem":"Debian:12","name":"bash","version":"5.2.15-2"},{"ecosystem":"Debian:12","name":"curl","version":"7.88.1-10"},{"ecosystem":"Debian:12","name":"sudo","version":"1.9.13p3-1"}]' >"$work/inventory/real-1.json"
/usr/bin/time -v -o "$work/time.txt" /tmp/ostyr-vuln "$work/service.yaml" 2>"$work/service.log" &
timed_pid=$!
for attempt in $(seq 1 600); do
    [[ "$(grep -cE "round done|feed not loaded|archive retains more than" "$work/service.log" 2>/dev/null || true)" -ge "$ROUNDS" ]] && break
    sleep 1
done
echo "rounds_seen=$(grep -c 'round done' "$work/service.log" || true)"
sleep 3
service_pid="$(pgrep -n -x ostyr-vuln || true)"
if [[ -z "$UNFILTERED" ]]; then
    grep "OSV archive read" "$work/service.log"
    grep "round done" "$work/service.log" | head -1
    grep -E "round (complete|incomplete)" "$work/service.log" | head -1
    [[ "$ARCHIVE" == all.zip ]] || echo "hostile archive: finding checks skipped"
    [[ "$ARCHIVE" != all.zip ]] || check "findings are stored for the real inventory" "1" "$(( $(sql "SELECT count(*) FROM vuln_findings WHERE tenant = 'acme' AND asset = 'real-1' AND resolved_micros IS NULL") > 0 ? 1 : 0 ))"
    [[ "$ARCHIVE" != all.zip ]] || check "only Debian:12 findings are stored" "Debian:12" "$(sql "SELECT string_agg(DISTINCT ecosystem, ',') FROM vuln_findings WHERE tenant = 'acme'")"
    sql "SELECT package, record_id, installed_version, fixed_version, kev FROM vuln_findings WHERE tenant = 'acme' AND asset = 'real-1' AND resolved_micros IS NULL ORDER BY priority DESC, package, record_id LIMIT 8"
    sql "SELECT 'open', count(*), count(*) FILTER (WHERE kev) FROM vuln_findings WHERE tenant = 'acme' AND asset = 'real-1' AND resolved_micros IS NULL"
else
    check "the unfiltered archive is refused loudly" "1" "$(grep -c 'archive retains more than' "$work/service.log" || true)"
    check "nothing is scanned without a feed" "0" "$(sql "SELECT count(*) FROM vuln_findings")"
fi
[[ -n "$service_pid" ]] && kill -TERM "$service_pid"
wait "$timed_pid" || true
service_pid=""
grep -E "Maximum resident|Elapsed" "$work/time.txt"
echo "failures=$failures"
exit "$failures"
REMOTE
