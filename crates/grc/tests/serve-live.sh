#!/usr/bin/env bash
# Usage: crates/grc/tests/serve-live.sh <lab-state-dir>
# Live check of ostyr-grc on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the service and the real cases_indicators producer run on the client VM over TLS
# against a scratch database of the datastore VM that holds the cases migrations and the grc migration (applied by the service). Reports are read back by psql.
# Every line is a check; the script exits with the failure count.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: serve-live.sh <lab-state-dir>}"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || { echo "datastore and client VMs are required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
target="$here/target/x86_64-unknown-linux-musl/release"
[[ -x "$target/ostyr-grc" && -x "$target/examples/cases_indicators" ]] || { echo "build it first: cargo build --release --target x86_64-unknown-linux-musl -p grc --bin ostyr-grc -p cases --example cases_indicators" >&2; exit 2; }

datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
owner="$(datastore_ssh "sudo grep '^POSTGRES_USER=' /etc/ostyr-lab/datastore.env" | cut -d= -f2)"
database="grc_live_$$"
datastore_ssh "sudo -u postgres createdb -O '$owner' '$database'"
trap 'datastore_ssh "sudo -u postgres dropdb --if-exists '"$database"'" || true' EXIT

scp "${ssh_options[@]}" "$target/ostyr-grc" "$target/examples/cases_indicators" "$client_user@$client_address:/tmp/"
scp "${ssh_options[@]}" "$here"/crates/cases/migrations/00[1-4]_*.sql "$client_user@$client_address:/tmp/"
ssh "${ssh_options[@]}" "$client_user@$client_address" "DB=$database bash -s" <<'REMOTE'
set -uo pipefail
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
work="$(mktemp -d)"
service_pid=""
trap '[[ -z "$service_pid" ]] || kill "$service_pid" 2>/dev/null; rm -rf "$work"' EXIT
printf '%s' "$POSTGRES_PASSWORD" >"$work/password"
chmod 600 "$work/password"
export PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full PGSSLROOTCERT=/etc/ostyr-lab/ca.pem
P() { psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DB" "$@"; }
failures=0
check() { if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi; }
contains() { if [[ "$3" == *"$2"* ]]; then echo "PASS $1: found $2"; else echo "FAIL $1: expected [$2] in [$3]"; failures=$((failures + 1)); fi; }
reports() { P -c "SELECT count(*) FROM grc_report WHERE tenant = 'acme'"; }
waitfor() { local i; for i in $(seq 120); do if grep -q "$1" "$work/err.log"; then return 0; fi; sleep 1; done; return 1; }
rounds() { grep -c "grc round done" "$work/err.log" || true; }
waitrounds() { local i; for i in $(seq 120); do if [[ "$(rounds)" -ge "$1" ]]; then return 0; fi; sleep 1; done; return 1; }

for file in 001_cases 002_link_attribution 003_observable_index 004_close_columns; do P -f /tmp/$file.sql >/dev/null; done
P -c "INSERT INTO cases (tenant,id,title,severity,status,resolution,created_at,updated_at,version,tasks,observables,comments,history,closed_at,ever_incident) VALUES
('acme','c1','t','low','closed','true_positive',(extract(epoch from now())::bigint - 36000),(extract(epoch from now())::bigint),2,'[]','[]','[]','[]',(extract(epoch from now())::bigint),true)"
cat >"$work/pg.yaml" <<YAML
host: $DATASTORE_DOMAIN
port: $POSTGRES_PORT
database: $DB
user: $POSTGRES_USER
password_file: $work/password
ca_file: /etc/ostyr-lab/ca.pem
statement_timeout_secs: 10
YAML
mkdir "$work/indicators"
/tmp/cases_indicators "$work/pg.yaml" acme now >"$work/indicators/cases.json"
contains "the real producer printed the incident indicator" "incident.mean_hours_to_close" "$(cat "$work/indicators/cases.json")"
write_manual() {
    printf 'evidence:\n  - tenant: acme\n    control: art21-2-a\n    owner: %s\n    recorded_at: 2026-11-01T08:00:00Z\n    review_until: 2099-11-01T08:00:00Z\n' "$1" >"$work/manual.new"
    mv "$work/manual.new" "$work/manual.yaml"
}
write_settings() {
    printf 'tenant: %s\npg_settings: %s/pg.yaml\naudit_file: %s/audit.log\nindicators_dir: %s/indicators\nmanual_file: %s/manual.yaml\nframeworks: [builtin:nis2]\ninterval_seconds: 300\nmax_reports: %s\n' \
        "$1" "$work" "$work" "$work" "$work" "$2" >"$work/settings.new"
    mv "$work/settings.new" "$work/settings.yaml"
}
write_manual ciso
write_settings acme 1000
/tmp/ostyr-grc "$work/settings.yaml" 2>"$work/err.log" &
service_pid=$!
waitfor "grc round done"
check "first round stored one report" 1 "$(reports)"
check "art21-2-b (incident hours, 10 h, at most 72) is compliant from the real producer" compliant \
    "$(P -c "SELECT c->>'status' FROM grc_report, jsonb_array_elements(body::jsonb->'controls') c WHERE c->>'id' = 'art21-2-b'")"
check "art21-2-a (manual) is compliant" compliant "$(P -c "SELECT c->>'status' FROM grc_report, jsonb_array_elements(body::jsonb->'controls') c WHERE c->>'id' = 'art21-2-a'")"
check "a control with no producer is named not assessable" "not assessable" \
    "$(P -c "SELECT c->>'status' FROM grc_report, jsonb_array_elements(body::jsonb->'controls') c WHERE c->>'id' = 'art21-2-e'")"

write_manual dpo
waitrounds 2 || echo "FAIL second round not seen"
check "a manual edit applied without restart: second report" 2 "$(reports)"
contains "the reload was applied" "configuration reloaded" "$(cat "$work/err.log")"
contains "the reload is audited under tenant all" '"tenant":"all"' "$(cat "$work/audit.log")"
contains "the audit names the changed manual record" "manual.art21-2-a" "$(cat "$work/audit.log")"

echo "ATTACK 1: hostile indicator files, refused alone and named"
printf '[{"tenant":"acme","tenant":"acme","name":"x","value":1,"observed_at":"2026-11-26T09:00:00Z","source":"t"}]' >"$work/indicators/dupkey.json"
printf '[{"tenant":"acme","name":"x","value":NaN,"observed_at":"2026-11-26T09:00:00Z","source":"t"}]' >"$work/indicators/nan.json"
printf '[{"tenant":"acme","name":"x","value":1e999,"observed_at":"2026-11-26T09:00:00Z","source":"t"}]' >"$work/indicators/huge.json"
truncate -s 5M "$work/indicators/big.json"
mkfifo "$work/indicators/fifo.json"
cp "$work/indicators/cases.json" "$work/indicators/cases-copy.json"
before="$(rounds)"
kill -HUP "$service_pid"
waitrounds $((before + 1)) || echo "FAIL no round after the hangup"
for name in dupkey nan huge big fifo; do contains "$name.json refused and named" "$name.json" "$(grep 'indicator file refused' "$work/err.log")"; done
contains "the name given in two files is dropped and named" "incident.mean_hours_to_close" "$(grep 'given more than once' "$work/err.log")"
contains "the round still completed" "refused_files=5" "$(grep 'indicator files read' "$work/err.log" | tail -1)"
check "art21-2-b has no evidence once its indicator is ambiguous" "not assessable" \
    "$(P -c "SELECT c->>'status' FROM grc_report, jsonb_array_elements(body::jsonb->'controls') c WHERE c->>'id' = 'art21-2-b' ORDER BY grc_report.id DESC LIMIT 1")"
rm -f "$work/indicators/dupkey.json" "$work/indicators/nan.json" "$work/indicators/huge.json" "$work/indicators/big.json" "$work/indicators/fifo.json" "$work/indicators/cases-copy.json"

echo "ATTACK 2: a refused manual file leaves the old snapshot in force"
before="$(rounds)"
reports_before="$(reports)"
printf 'evidence: nope\n' >"$work/manual.bad"
mv "$work/manual.bad" "$work/manual.yaml"
waitfor "configuration reload refused" || echo "FAIL the bad manual file was not refused"
kill -HUP "$service_pid"
waitrounds $((before + 1)) || echo "FAIL no round after the hangup"
contains "the refusal is audited as denied" '"outcome":"denied"' "$(cat "$work/audit.log")"
check "the round used the old record: no new report" "$reports_before" "$(P -c "SELECT count(*) FROM grc_report WHERE tenant = 'acme'")"
write_manual dpo

echo "ATTACK 3: start-only settings and the report cap"
write_settings globex 1000
kill -HUP "$service_pid"
sleep 2
contains "a tenant change is refused" "another tenant" "$(grep 'configuration reload refused' "$work/err.log" | tail -1)"
contains "the old tenant stays in force" "acme" "$(P -c "SELECT DISTINCT tenant FROM grc_report")"
before="$(rounds)"
write_settings acme 2
kill -HUP "$service_pid"
waitrounds $((before + 1)) || echo "FAIL no round after the cap setting"
reports_before="$(reports)"
write_manual cto
waitfor "report cap reached" || echo "FAIL no cap line"
contains "the cap is an error line naming the framework" "framework=\"nis2\"" "$(grep 'report cap reached' "$work/err.log" | tail -1)"
check "nothing stored and nothing deleted at the cap" "$reports_before" "$(reports)"

echo "SIGTERM twice: the round finishes, the second signal is ignored, exit 0"
kill -TERM "$service_pid"
kill -TERM "$service_pid"
wait "$service_pid"
code=$?
service_pid=""
check "exit code" 0 "$code"
contains "the stop was announced" "stop requested" "$(cat "$work/err.log")"
contains "the process stopped by itself" "stopped rounds=" "$(cat "$work/err.log")"
echo "failures=$failures"
exit "$failures"
REMOTE
