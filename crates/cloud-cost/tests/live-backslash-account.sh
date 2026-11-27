#!/usr/bin/env bash
# Usage: crates/cloud-cost/tests/live-backslash-account.sh <task-id> [bin-dir]
# Live proof (T976) on a datastore-pair lab: a corrected export of accounts CORP\x, a'b and plain replaces the first one, none of the old rows survive.
# bin-dir holds the musl cost_load and cost_read examples (default target/x86_64-unknown-linux-musl/debug/examples).
# Every ssh, scp, curl and remote run is bounded by the constants below, so a dead peer ends the script with a named failure.
set -euo pipefail

readonly SSH_CONNECT_TIMEOUT_SECONDS=10
readonly SSH_ALIVE_INTERVAL_SECONDS=5
readonly SSH_ALIVE_COUNT_MAX=3
readonly CURL_CONNECT_TIMEOUT_SECONDS=5
readonly CURL_MAX_TIME_SECONDS=30
readonly REMOTE_STEP_TIMEOUT_SECONDS=60
readonly REMOTE_TOTAL_TIMEOUT_SECONDS=300

source "$(dirname "${BASH_SOURCE[0]}")/../../../lab/lib.sh"

task_id="${1:?usage: live-backslash-account.sh <task-id> [bin-dir]}"
bin_dir="${2:-$REPO_DIR/target/x86_64-unknown-linux-musl/debug/examples}"
lab_state="$(state_dir "$task_id")"
client_line="$(grep '^client ' "$lab_state/vms.txt")"
read -r _ client_user client_address <<<"$client_line"
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
    -o ConnectTimeout="$SSH_CONNECT_TIMEOUT_SECONDS" -o ServerAliveInterval="$SSH_ALIVE_INTERVAL_SECONDS" -o ServerAliveCountMax="$SSH_ALIVE_COUNT_MAX")

timeout "$REMOTE_STEP_TIMEOUT_SECONDS" ssh -n "${ssh_options[@]}" "$client_user@$client_address" "rm -rf /tmp/t976 && mkdir /tmp/t976"
timeout "$REMOTE_STEP_TIMEOUT_SECONDS" scp "${ssh_options[@]}" "$bin_dir/cost_load" "$bin_dir/cost_read" "$client_user@$client_address:/tmp/t976/"
timeout "$REMOTE_TOTAL_TIMEOUT_SECONDS" ssh "${ssh_options[@]}" "$client_user@$client_address" \
    "bash -s -- $CURL_CONNECT_TIMEOUT_SECONDS $CURL_MAX_TIME_SECONDS $REMOTE_STEP_TIMEOUT_SECONDS" <<'REMOTE'
set -euo pipefail
curl_connect_timeout="$1"
curl_max_time="$2"
step_timeout="$3"
cd /tmp/t976
sudo grep '^CLICKHOUSE_PASSWORD=' /etc/ostyr-lab/datastore.env | cut -d= -f2- | tr -d '\n' >ch.password
chmod 600 ch.password
cat >settings.yaml <<YAML
url: https://datastore.lab.test:8443
user: ostyr
password_file: /tmp/t976/ch.password
ca_file: /etc/ostyr-lab/ca.pem
database: t976
table: cloud_cost_daily
tenant: acme
YAML
chmod 600 settings.yaml
ch() {
    curl -sS --fail --connect-timeout "$curl_connect_timeout" --max-time "$curl_max_time" --cacert /etc/ostyr-lab/ca.pem \
        -u "ostyr:$(cat /tmp/t976/ch.password)" "https://datastore.lab.test:8443/" --data-binary "$1"
}
ch 'DROP DATABASE IF EXISTS t976 SYNC'
ch 'CREATE DATABASE t976'
header='BilledCost,BillingCurrency,BillingAccountId,ChargePeriodStart,ServiceName,Tags'
mkexport() {
    printf '%s\n' "$header" "$1,USD,CORP\\x,2026-11-01T00:00:00Z,compute,\"{}\"" "$2,USD,a'b,2026-11-01T00:00:00Z,compute,\"{}\"" "$3,USD,plain,2026-11-01T00:00:00Z,compute,\"{}\""
}
mkexport 10 20 30 >first.csv
mkexport 11 21 31 >second.csv
timeout "$step_timeout" ./cost_load first.csv settings.yaml
test "$(ch "SELECT count() FROM t976.cloud_cost_daily FINAL WHERE tenant = 'acme' AND dimension = 'total'")" = 3
timeout "$step_timeout" ./cost_load second.csv settings.yaml
digest_second="$(sha256sum second.csv | cut -d' ' -f1)"
echo "--- stored rows of dimension total, FINAL"
ch "SELECT account, source = '$digest_second' AS is_new, toString(cost) FROM t976.cloud_cost_daily FINAL WHERE tenant = 'acme' AND dimension = 'total' ORDER BY account FORMAT TSV"
echo "--- cost_read"
timeout "$step_timeout" ./cost_read settings.yaml acme 2026-11-01 2026-11-01 total | tee read.out
rows_stored="$(ch "SELECT count() FROM t976.cloud_cost_daily FINAL WHERE tenant = 'acme' AND dimension = 'total'")"
rows_old="$(ch "SELECT count() FROM t976.cloud_cost_daily FINAL WHERE tenant = 'acme' AND dimension = 'total' AND source != '$digest_second'")"
echo "stored=$rows_stored old=$rows_old"
test "$rows_stored" = 3
test "$rows_old" = 0
tab="$(printf '\t')"
for expected in "CORP\\u{5c}x${tab}$digest_second${tab}total${tab}${tab}${tab}11${tab}USD" "a'b${tab}$digest_second${tab}total${tab}${tab}${tab}21${tab}USD" \
    "plain${tab}$digest_second${tab}total${tab}${tab}${tab}31${tab}USD"; do
    grep -Fxq "2026-11-01${tab}$expected" read.out
done
grep -Fxq 'rows 3' read.out
echo "PASS: one row set per account from the new source"
REMOTE
