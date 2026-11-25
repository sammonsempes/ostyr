#!/usr/bin/env bash
# Usage: cd compose && sudo bash -s -- <curl-image> <clickhouse-proof.sh   (run by compose-lab.sh inside the VM, never on the host)
# Talks to ClickHouse from a throwaway container on the compose network and prints one "key value" line per proof; the caller compares the values.
set -uo pipefail

IMAGE="${1:?usage: clickhouse-proof.sh <curl-image>}"
SECRETS="$PWD/secrets"
readonly IMAGE SECRETS
readonly CURL_COMMON=(curl -sS --max-time 20 --cacert /s/ca.crt)

ch() {
    local user="$1" statement="$2" extra="${3:-}"
    docker run --rm --network ostyr_default -v "$SECRETS:/s:ro" "$IMAGE" sh -c \
        'curl -sS --max-time 20 --cacert /s/ca.crt -u "$1:$(cat /s/clickhouse_$1_password)" --data-binary "$2" "https://clickhouse:8443/?database=ostyr$3" 2>&1' _ "$user" "$statement" "$extra"
}

code_of() {
    sed -n 's/^Code: \([0-9]*\).*/\1/p' | head -n 1
}

probe() {
    docker run --rm --network ostyr_default "$IMAGE" sh -c "curl -sS --max-time 8 -o /dev/null '$1' >/dev/null 2>&1; echo \$?"
}

printf 'objects %s\n' "$(ch schema "SELECT count() FROM system.tables WHERE database = 'ostyr'")"
printf 'reader_select %s\n' "$(ch reader 'SELECT count() FROM events')"
printf 'reader_insert_code %s\n' "$(ch reader "INSERT INTO events (\`@timestamp\`, tenant, tenant_tier) VALUES (now(), 'proof', 'standard')" | code_of)"
printf 'reader_lift_readonly_code %s\n' "$(ch reader 'SELECT 1' '&readonly=0' | code_of)"
printf 'reader_insert_text %s\n' "$(ch reader "INSERT INTO events (\`@timestamp\`, tenant, tenant_tier) VALUES (now(), 'proof', 'standard')" | head -n 1 | cut -c1-200)"
printf 'reader_count_after_refused %s\n' "$(ch reader 'SELECT count() FROM events')"
printf 'ingest_insert %s\n' "$(ch ingest "INSERT INTO events (\`@timestamp\`, tenant, tenant_tier) VALUES (now(), 'proof', 'standard')" | wc -c)"
printf 'ingest_select_code %s\n' "$(ch ingest 'SELECT count() FROM events' | code_of)"
printf 'reader_count_after_insert %s\n' "$(ch reader 'SELECT count() FROM events')"
printf 'metrics_insert %s\n' "$(ch metrics "INSERT INTO metric_samples (tenant, metric, unit, kind, labels, \`@timestamp\`, value) VALUES ('proof', 'cpu', 'percent', 'gauge', map(), now(), 1.5)" | wc -c)"
printf 'rollup_rows %s\n' "$(ch reader 'SELECT count() FROM metric_rollup_1m')"
printf 'metrics_events_code %s\n' "$(ch metrics "INSERT INTO events (\`@timestamp\`, tenant, tenant_tier) VALUES (now(), 'proof', 'standard')" | code_of)"
printf 'ingest_metrics_code %s\n' "$(ch ingest "INSERT INTO metric_samples (tenant, metric, unit, kind, labels, \`@timestamp\`, value) VALUES ('proof', 'cpu', 'percent', 'gauge', map(), now(), 1.5)" | code_of)"
printf 'reader_ddl_code %s\n' "$(ch reader 'DROP TABLE events' | code_of)"
printf 'ingest_ddl_code %s\n' "$(ch ingest 'DROP TABLE events' | code_of)"
printf 'schema_changed_settings %s\n' "$(ch schema "SELECT name FROM system.settings WHERE changed" | tr '\n' ',')"
printf 'reader_changed_settings %s\n' "$(ch reader "SELECT name FROM system.settings WHERE changed" | tr '\n' ',')"
printf 'reader_readonly %s\n' "$(ch reader "SELECT value FROM system.settings WHERE name = 'readonly'")"
printf 'wrong_password_code %s\n' "$(docker run --rm --network ostyr_default -v "$SECRETS:/s:ro" "$IMAGE" "${CURL_COMMON[@]}" -u reader:wrong --data-binary 'SELECT 1' https://clickhouse:8443/ 2>&1 | code_of)"
printf 'default_user_code %s\n' "$(docker run --rm --network ostyr_default -v "$SECRETS:/s:ro" "$IMAGE" "${CURL_COMMON[@]}" --data-binary 'SELECT 1' https://clickhouse:8443/ 2>&1 | code_of)"
printf 'default_empty_password_code %s\n' "$(docker run --rm --network ostyr_default -v "$SECRETS:/s:ro" "$IMAGE" "${CURL_COMMON[@]}" -u default: --data-binary 'SELECT 1' https://clickhouse:8443/ 2>&1 | code_of)"
printf 'name_check %s\n' "$(docker run --rm --network ostyr_default -v "$SECRETS:/s:ro" "$IMAGE" "${CURL_COMMON[@]}" https://clickhouse:8443/ping 2>&1)"
printf 'wrong_name %s\n' "$(docker run --rm --network ostyr_default -v "$SECRETS:/s:ro" "$IMAGE" "${CURL_COMMON[@]}" --resolve ostyr.invalid:8443:"$(docker inspect -f '{{(index .NetworkSettings.Networks "ostyr_default").IPAddress}}' "$(docker compose ps -q clickhouse)")" https://ostyr.invalid:8443/ping 2>&1 | grep -c 'no alternative certificate subject name')"
printf 'plain_http_8123 %s\n' "$(probe http://clickhouse:8123/ping)"
printf 'native_9000 %s\n' "$(probe http://clickhouse:9000/)"
printf 'native_tls_9440 %s\n' "$(probe https://clickhouse:9440/)"
printf 'mysql_9004 %s\n' "$(probe http://clickhouse:9004/)"
printf 'postgres_9005 %s\n' "$(probe http://clickhouse:9005/)"
printf 'plain_on_tls_port %s\n' "$(probe http://clickhouse:8443/ping)"
