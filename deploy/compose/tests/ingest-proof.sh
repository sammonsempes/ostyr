#!/usr/bin/env bash
# Usage: cd compose && sudo bash -s -- <nats-box image> < ingest-proof.sh   (run by compose-lab.sh inside the VM, never on the host)
# After the proof agent sent its batch: reads back, as the ClickHouse reader and through psql, what the siem, metrics and metricalerts services stored, then makes each
# service reload on SIGHUP and prints its audit lines. Prints one `key value` line per proof; the caller compares the values.
set -uo pipefail

IMAGE="${1:?usage: ingest-proof.sh <nats-box image>}"
SECRETS="$PWD/secrets"
readonly IMAGE SECRETS
readonly ATTEMPTS=60
readonly PAUSE_SECONDS=5
readonly RELOAD_PAUSE_SECONDS=5

reader_query() {
    docker run --rm --network ostyr_default -v "$SECRETS:/s:ro" "$IMAGE" sh -c \
        'curl -sS --max-time 20 --cacert /s/ca.crt -u "reader:$(cat /s/clickhouse_reader_password)" --data-binary "$1" "https://clickhouse:8443/?database=ostyr" 2>&1' _ "$1"
}

alert_count() {
    local script
    script="PGPASSWORD=\"\$(cat /run/pgtls/service_password)\" psql \"host=postgres dbname=ostyr user=ostyr_service sslmode=verify-full sslrootcert=/run/secrets/pg_ca\" -At \
        -c \"select count(*) from alerts where tenant = 'default' and rule_id like '%host.cpu.high'\""
    docker compose exec -T postgres bash -s <<<"$script" 2>&1
}

wait_for_rows() {
    local value="none" _attempt
    for _attempt in $(seq 1 "$ATTEMPTS"); do
        value="$("$@" | tr -d '\n')"
        if [[ "$value" =~ ^[0-9]+$ && "$value" -ge 1 ]]; then
            break
        fi
        sleep "$PAUSE_SECONDS"
    done
    printf '%s' "$value"
}

event_rows() {
    reader_query "SELECT count() FROM events WHERE tenant = 'default' AND message = 't853 batch through the relay'"
}

metric_rows() {
    reader_query "SELECT count() FROM metric_samples WHERE tenant = 'default' AND metric = 'system.cpu.utilization'"
}

audit_of() {
    docker run --rm -v "ostyr_$1:/state:ro" "$IMAGE" cat /state/audit.log 2>&1
}

printf 'events_rows %s\n' "$(wait_for_rows event_rows)"
printf 'host_event_rows_in_events %s\n' "$(reader_query "SELECT count() FROM events WHERE event.dataset = 'ostyr.host_metrics'" | tr -d '\n')"
printf 'metric_rows %s\n' "$(wait_for_rows metric_rows)"
printf 'metric_value %s\n' "$(reader_query "SELECT max(value) FROM metric_samples WHERE tenant = 'default' AND metric = 'system.cpu.utilization'" | tr -d '\n')"
printf 'metric_tenants %s\n' "$(reader_query "SELECT groupArray(DISTINCT tenant) FROM metric_samples WHERE metric = 'system.cpu.utilization'" | tr -d '\n')"
printf 'alert_rows %s\n' "$(wait_for_rows alert_count)"
CONFIG="$PWD/config"
BACKUP="$(mktemp -d)"
readonly CONFIG BACKUP
cp -p "$CONFIG/siem-ingest.yaml" "$CONFIG/metrics-ingest.yaml" "$CONFIG/metric-alerts.yaml" "$BACKUP/"
sed -i 's|^nats_consumer: siem-ingest$|nats_consumer: siem-ingest\nmax_batch_age_seconds: 7|' "$CONFIG/siem-ingest.yaml"
sed -i 's|^ingest:$|ingest:\n  max_batch_age_seconds: 7|' "$CONFIG/metrics-ingest.yaml"
sed -i 's|^round_seconds: 30$|round_seconds: 31|' "$CONFIG/metric-alerts.yaml"
docker compose kill -s HUP siem metrics metricalerts >/dev/null 2>&1
sleep "$RELOAD_PAUSE_SECONDS"
cp -p "$BACKUP/siem-ingest.yaml" "$BACKUP/metrics-ingest.yaml" "$BACKUP/metric-alerts.yaml" "$CONFIG/"
rm -rf "$BACKUP"
docker compose kill -s HUP siem metrics metricalerts >/dev/null 2>&1
sleep "$RELOAD_PAUSE_SECONDS"
for volume in siemstate metricsstate alertsstate; do
    audit="$(audit_of "$volume")"
    printf '%s_audit_all %s\n' "$volume" "$(grep -c '"tenant":"all"' <<<"$audit")"
    printf '%s_audit_other %s\n' "$volume" "$(grep -v '"tenant":"all"' <<<"$audit" | grep -c '"tenant"')"
    printf '%s_audit_line %s\n' "$volume" "$(grep -m1 '"tenant":"all"' <<<"$audit" | cut -c1-300)"
done
