#!/usr/bin/env bash
# Usage: lab/tests/e2e-alert.sh <task-id>
# On a booted e2e-linux lab: runs `whoami` on the agent VM, then polls (capped attempts) until the event row is in ClickHouse, the alert row is in
# PostgreSQL and the alert title is on the GET /alerts page of the web UI fetched with a logged-in curl. Prints each stage with its timestamp and
# exits non-zero on the first stage that never arrives. Everything it creates lives in the lab state directory.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly TENANT="lab"
readonly ANALYST_USER="analyst"
readonly ANALYST_PASSWORD="Lab-Analyst-Pass-1"
readonly WEB_PORT=7445
readonly ALERT_TITLE="Whoami seen"
readonly STAGE_ATTEMPTS=90
readonly STAGE_DELAY_SECONDS=10
readonly SERVICE_ATTEMPTS=30
readonly SERVICE_DELAY_SECONDS=5
readonly CURL_TIMEOUT_SECONDS=20
readonly CLOCK_MARGIN_SECONDS=2

task_id="${1:?usage: e2e-alert.sh <task-id>}"
lab_state="$(state_dir "$task_id")"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || die "vms.txt lacks the datastore and client VMs"
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
datastore_ssh() { ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "$@"; }
client_ssh() { ssh -n "${ssh_options[@]}" "$client_user@$client_address" "$@"; }

stage() {
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1"
}

clickhouse_count() {
    local query encoded
    query="SELECT count() FROM ostyr.events WHERE tenant = '$TENANT' AND \`process.executable\` LIKE '%/whoami' AND \`@timestamp\` >= toDateTime64($1, 3, 'UTC')"
    encoded="$(printf '%s' "$query" | base64 -w 0)"
    ssh "${ssh_options[@]}" "$datastore_user@$datastore_address" "sudo bash -s $encoded" <<'REMOTE'
set -euo pipefail
source /etc/ostyr-lab/datastore.env
curl --fail --silent --show-error --cacert "$DATASTORE_CA" --user "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" --data-binary "$(base64 -d <<<"$1")" \
    "https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT/"
REMOTE
}

alert_count() {
    datastore_ssh "sudo -u postgres psql -d ostyr --tuples-only --no-align --quiet -c \"SELECT count(*) FROM alerts WHERE tenant = '$TENANT' AND rule_title = '$ALERT_TITLE'\""
}

wait_for_stage() {
    local description="$1" attempt result
    shift
    for ((attempt = 0; attempt < STAGE_ATTEMPTS; attempt++)); do
        result="$("$@" 2>/dev/null || true)"
        if [[ -n "$result" ]]; then
            stage "stage ok: $description ($result)"
            return 0
        fi
        sleep "$STAGE_DELAY_SECONDS"
    done
    stage "stage FAILED: $description never arrived after $STAGE_ATTEMPTS attempts"
    return 1
}

for ((attempt = 0; attempt < SERVICE_ATTEMPTS; attempt++)); do
    if datastore_ssh "systemctl is-active --quiet ostyr-event-gateway ostyr-siem-ingest ostyr-detection ostyr-alerts-api ostyr-web-ui" 2>/dev/null &&
        client_ssh "systemctl is-active --quiet tetragon ostyr-linux-agent" 2>/dev/null; then
        break
    fi
    sleep "$SERVICE_DELAY_SECONDS"
done
datastore_ssh "systemctl is-active ostyr-event-gateway ostyr-siem-ingest ostyr-detection ostyr-alerts-api ostyr-web-ui" >/dev/null || die "an Ostyr service is not active on the datastore VM"
client_ssh "systemctl is-active tetragon ostyr-linux-agent" >/dev/null || die "Tetragon or the Linux agent is not active on the client VM"
stage "services active"

baseline_alerts="$(alert_count)"
started="$(client_ssh "date +%s")"
since=$((started - CLOCK_MARGIN_SECONDS))
stage "running whoami on the agent VM (alerts before: $baseline_alerts)"
client_ssh "whoami" >/dev/null

event_arrived() {
    local count
    count="$(clickhouse_count "$since")"
    if [[ "$count" -gt 0 ]]; then printf '%s whoami rows' "$count"; fi
}
alert_arrived() {
    local count
    count="$(alert_count)"
    if [[ "$count" -gt "$baseline_alerts" ]]; then printf '%s alerts' "$count"; fi
}
cookie_jar="$lab_state/e2e-cookies"
web_url="https://$datastore_address:$WEB_PORT"
web_curl() {
    curl --fail --silent --show-error --max-time "$CURL_TIMEOUT_SECONDS" --cacert "$lab_state/e2e-stage/pki/platform.pem" --cookie "$cookie_jar" --cookie-jar "$cookie_jar" "$@"
}
alert_in_ui() {
    local token page
    rm -f "$cookie_jar"
    token="$(web_curl "$web_url/login" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -n 1)"
    [[ -n "$token" ]] || return 0
    web_curl --output /dev/null --data-urlencode "csrf=$token" --data-urlencode "username=$ANALYST_USER" --data-urlencode "password=$ANALYST_PASSWORD" \
        "$web_url/login" || return 0
    page="$(web_curl "$web_url/alerts")"
    if grep -q "$ALERT_TITLE" <<<"$page"; then printf 'title on the alert queue page'; fi
}

wait_for_stage "event row in ClickHouse" event_arrived
wait_for_stage "alert row in PostgreSQL" alert_arrived
wait_for_stage "alert title on GET /alerts of the web UI" alert_in_ui
rm -f "$cookie_jar"
stage "end to end proof complete"
