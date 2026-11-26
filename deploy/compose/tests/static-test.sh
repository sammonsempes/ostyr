#!/usr/bin/env bash
# Usage: deploy/compose/tests/static-test.sh
# Static checks of the compose files on the host: docker compose config when Docker is installed, shellcheck when installed, and greps for
# the hardening the deployment promises. Builds and runs nothing.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$(dirname "$TESTS_DIR")"
readonly TESTS_DIR COMPOSE_DIR
readonly COMPOSE_FILE="${STATIC_TEST_COMPOSE_FILE:-$COMPOSE_DIR/compose.yaml}"
readonly CH_INIT_FILE="${STATIC_TEST_INIT_FILE:-$COMPOSE_DIR/init.sh}"
readonly CH_CONFIG_FILE="${STATIC_TEST_CH_CONFIG_FILE:-$COMPOSE_DIR/config/clickhouse-config.xml}"
readonly CH_SCHEMA_FILE="${STATIC_TEST_CH_SCHEMA_FILE:-$COMPOSE_DIR/config/clickhouse-schema.sql}"
readonly CONFIG_DIR="${STATIC_TEST_CONFIG_DIR:-$COMPOSE_DIR/config}"
readonly PROJECT_DIR="${STATIC_TEST_PROJECT_DIR:-$COMPOSE_DIR}"
readonly ALLOWED_KEYS="name services postgres platform web image restart read_only cap_drop cap_add security_opt environment POSTGRES_PASSWORD_FILE entrypoint command secrets volumes tmpfs healthcheck test interval timeout retries pull_policy depends_on condition networks default ipv4_address ports ipam config subnet ip_range pgdata state webstate playbooks playbooksstate user file pg_password pg_service_password pg_server_key pg_server_cert pg_ca playbooks_pg_password api_tls_key api_tls_cert store_key nats gateway relay natsdata gatewaystate relaystate gateway_tls_key gateway_tls_cert nats_server_key nats_server_cert nats_conf agent_ca nats_gateway_password RUST_LOG clickhouse chschema chdata clickhouse_server_key clickhouse_server_cert clickhouse_users clickhouse_schema_password CLICKHOUSE_WATCHDOG_ENABLE siem metrics metricalerts siemstate metricsstate alertsstate clickhouse_ingest_password clickhouse_metrics_password nats_siem_password nats_metrics_password metricalerts_pg_password metricalerts_clickhouse_password ${STATIC_TEST_EXTRA_KEYS:-}"
readonly FLOW_KEYS="cap_drop cap_add security_opt secrets command test"
readonly BLOCK_KEYS="ports volumes services networks"
failures=0

expect() {
    local description="$1"
    shift
    if "$@"; then
        printf 'ok   %s\n' "$description"
    else
        printf 'FAIL %s\n' "$description"
        failures=$((failures + 1))
    fi
}

absent() {
    ! "$@"
}

count_lines() {
    grep -c -- "$1" "$COMPOSE_FILE" || true
}

all_services_hardened() {
    local services
    services="$(grep -c '^    image:' "$COMPOSE_FILE")"
    [[ "$(count_lines '^    read_only: true$')" -eq "$services" && "$(count_lines '^    cap_drop: \[ALL\]$')" -eq "$services" \
        && "$(count_lines 'no-new-privileges:true')" -eq "$services" ]]
}

images_are_pinned() {
    ! grep '^    image:' "$COMPOSE_FILE" | grep -v -e '@sha256:[0-9a-f]\{64\}$' -e 'image: ostyr-platform:local$'
}

web_service() {
    awk '/^  web:$/ {inside = 1; print; next} /^  [^ ]/ || /^[^ ]/ {inside = 0} inside' "$COMPOSE_FILE"
}

playbooks_service() {
    awk '/^  playbooks:$/ {inside = 1; print; next} /^  [^ ]/ || /^[^ ]/ {inside = 0} inside' "$COMPOSE_FILE"
}

nats_service() {
    awk '/^  nats:$/ {inside = 1; print; next} /^  [^ ]/ || /^[^ ]/ {inside = 0} inside' "$COMPOSE_FILE"
}

gateway_service() {
    awk '/^  gateway:$/ {inside = 1; print; next} /^  [^ ]/ || /^[^ ]/ {inside = 0} inside' "$COMPOSE_FILE"
}

relay_service() {
    awk '/^  relay:$/ {inside = 1; print; next} /^  [^ ]/ || /^[^ ]/ {inside = 0} inside' "$COMPOSE_FILE"
}

clickhouse_service() {
    awk '/^  clickhouse:$/ {inside = 1; print; next} /^  [^ ]/ || /^[^ ]/ {inside = 0} inside' "$COMPOSE_FILE"
}

chschema_service() {
    awk '/^  chschema:$/ {inside = 1; print; next} /^  [^ ]/ || /^[^ ]/ {inside = 0} inside' "$COMPOSE_FILE"
}

named_service() {
    awk -v name="  $1:" '$0 == name {inside = 1; print; next} /^  [^ ]/ || /^[^ ]/ {inside = 0} inside' "$COMPOSE_FILE"
}

consumer_is_hardened() {
    local name="$1" uid="$2" secrets="$3" command="$4" state="$5" block
    block="$(named_service "$name")"
    grep -qx '    read_only: true' <<<"$block" && grep -qx '    cap_drop: \[ALL\]' <<<"$block" && grep -qF 'no-new-privileges:true' <<<"$block" \
        && grep -qx "    user: $uid:$uid" <<<"$block" && grep -qxF "    secrets: [$secrets]" <<<"$block" \
        && grep -qxF "    command: [$command]" <<<"$block" && grep -qx '    image: ostyr-platform:local' <<<"$block" \
        && [[ "$(service_items "$name" volumes)" == '      - ./config:/etc/ostyr:ro'$'\n'"      - $state" ]] \
        && ! grep -q -e '^    ports:' -e 'cap_add' -e 'network_mode' -e 'store_key' -e 'api_tls' -e 'gateway_tls' -e 'nats_conf' -e 'nats_admin' -e 'nats_gateway' <<<"$block"
}

siem_is_hardened() {
    consumer_is_hardened siem 65529 'pg_ca, clickhouse_ingest_password, nats_siem_password' '"/usr/local/bin/ostyr-siem-ingest", "/etc/ostyr/siem-ingest.yaml"' siemstate:/var/lib/ostyr-siem \
        && ! named_service siem | grep -q -e clickhouse_metrics -e nats_metrics -e metricalerts -e pg_service_password -e clickhouse_users -e clickhouse_schema
}

metrics_is_hardened() {
    consumer_is_hardened metrics 65528 'pg_ca, clickhouse_metrics_password, nats_metrics_password' '"/usr/local/bin/ostyr-metrics-ingest", "/etc/ostyr/metrics-ingest.yaml"' \
        metricsstate:/var/lib/ostyr-metrics \
        && ! named_service metrics | grep -q -e clickhouse_ingest -e nats_siem -e metricalerts -e pg_service_password -e clickhouse_users -e clickhouse_schema
}

metricalerts_is_hardened() {
    consumer_is_hardened metricalerts 65527 'pg_ca, metricalerts_pg_password, metricalerts_clickhouse_password' \
        '"/usr/local/bin/ostyr-metric-alerts", "/etc/ostyr/metric-alerts.yaml"' alertsstate:/var/lib/ostyr-metric-alerts \
        && ! named_service metricalerts | grep -q -e clickhouse_ingest -e clickhouse_metrics -e nats_ -e pg_service_password -e clickhouse_users -e clickhouse_schema
}

ingest_files_use_only_their_secrets() {
    ! grep -h -o '/run/secrets/[a-z_.]*' "$CONFIG_DIR/siem-ingest.yaml" | grep -v -x -e /run/secrets/pg_ca -e /run/secrets/clickhouse_ingest_password -e /run/secrets/nats_siem_password \
        && ! grep -h -o '/run/secrets/[a-z_.]*' "$CONFIG_DIR/metrics-ingest.yaml" | grep -v -x -e /run/secrets/pg_ca -e /run/secrets/clickhouse_metrics_password -e /run/secrets/nats_metrics_password \
        && ! grep -h -o '/run/secrets/[a-z_.]*' "$CONFIG_DIR"/metric-alerts*.yaml | grep -v -x -e /run/secrets/pg_ca -e /run/secrets/metricalerts_pg_password -e /run/secrets/metricalerts_clickhouse_password \
        && ! grep -h -o '/var/lib/[a-z-]*' "$CONFIG_DIR/siem-ingest.yaml" | grep -v -x /var/lib/ostyr-siem \
        && ! grep -h -o '/var/lib/[a-z-]*' "$CONFIG_DIR/metrics-ingest.yaml" | grep -v -x /var/lib/ostyr-metrics \
        && ! grep -h -o '/var/lib/[a-z-]*' "$CONFIG_DIR"/metric-alerts*.yaml | grep -v -x /var/lib/ostyr-metric-alerts
}

ingest_files_use_their_own_clickhouse_user() {
    grep -qx 'clickhouse_user: ingest' "$CONFIG_DIR/siem-ingest.yaml" && grep -qx '  clickhouse_user: metrics' "$CONFIG_DIR/metrics-ingest.yaml" \
        && grep -qx 'user: reader' "$CONFIG_DIR/metric-alerts-fetch.yaml" && grep -qx 'nats_user: siem_ingest' "$CONFIG_DIR/siem-ingest.yaml" \
        && grep -qx '  nats_user: metrics_ingest' "$CONFIG_DIR/metrics-ingest.yaml"
}

nats_consumer_accounts_are_scoped() {
    grep -qF 'readonly NATS_CONSUMERS=(SIEM:siem_ingest:siem-ingest METRICS:metrics_ingest:metrics-ingest)' "$CH_INIT_FILE" \
        && grep -qF 'accounts: [$account] }' "$CH_INIT_FILE" && grep -qF '{ service: "$NATS_DEAD_SUBJECT", accounts: [SIEM, METRICS] }' "$CH_INIT_FILE" \
        && grep -qF 'response_type: stream, response_threshold: "$NATS_PULL_THRESHOLD"' "$CH_INIT_FILE" \
        && grep -qF 'subscribe: { allow: ["_INBOX_$user.>"] }' "$CH_INIT_FILE" && ! grep -q -e 'CONSUMER.CREATE' -e 'CONSUMER.DURABLE' -e 'STREAM.PURGE' -e 'JS.API.>' "$CH_INIT_FILE"
}

nats_conf_matches_golden() {
    local work rendered outcome=0
    mkdir -p "$COMPOSE_DIR/../../target"
    work="$(mktemp -d "$COMPOSE_DIR/../../target/nats-conf.XXXXXX")"
    mkdir "$work/secrets"
    chmod 0700 "$work/secrets"
    cp "$CH_INIT_FILE" "$work/init.sh"
    if "$work/init.sh" golden.example >"$work/init.log" 2>&1; then
        rendered="$(
            ADMIN_PASSWORD="$(cat "$work/secrets/nats_admin_password")" GATEWAY_PASSWORD="$(cat "$work/secrets/nats_gateway_password")" \
                SIEM_PASSWORD="$(cat "$work/secrets/nats_siem_password")" METRICS_PASSWORD="$(cat "$work/secrets/nats_metrics_password")" \
                "$TESTS_DIR/mark-nats-passwords.sh" <"$work/secrets/nats.conf"
        )"
        [[ "$rendered" == "$(cat "$TESTS_DIR/expected-nats.conf")" ]] || outcome=1
    else
        outcome=1
    fi
    rm -rf "$work"
    [[ "$outcome" -eq 0 ]]
}

nats_init_refuses_other_conf() {
    local work outcome=0
    mkdir -p "$COMPOSE_DIR/../../target"
    work="$(mktemp -d "$COMPOSE_DIR/../../target/nats-refuse.XXXXXX")"
    mkdir "$work/secrets"
    chmod 0700 "$work/secrets"
    cp "$CH_INIT_FILE" "$work/init.sh"
    "$work/init.sh" refuse.example >"$work/first.log" 2>&1 || outcome=1
    "$work/init.sh" refuse.example >"$work/same.log" 2>&1 || outcome=1
    printf '\n' >>"$work/secrets/nats.conf"
    ! "$work/init.sh" refuse.example >"$work/edited.log" 2>&1 || outcome=1
    grep -q 'nats.conf is not the file init.sh renders' "$work/edited.log" || outcome=1
    rm -rf "$work"
    [[ "$outcome" -eq 0 ]]
}

init_refuses_planted_secrets() {
    local work outcome=0 name plant user
    local -a planted_list
    local -a names=(nats_gateway_password nats_admin_password nats_siem_password nats_metrics_password pg_password pg_service_password)
    local -a plants=('x",permissions:{publish:">"}},{user:q,pass:"' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' 'AAAAAAAAAAAAAAAAAAAAAA"AAAAAAAAAAAAAAAAAAAA=' 'AAAAAAAAAAAAAAAAAAAAAA}AAAAAAAAAAAAAAAAAAAA=' $'AAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAA=')
    mkdir -p "$COMPOSE_DIR/../../target"
    work="$(mktemp -d "$COMPOSE_DIR/../../target/planted.XXXXXX")"
    mkdir "$work/secrets"
    chmod 0700 "$work/secrets"
    cp "$CH_INIT_FILE" "$work/init.sh"
    "$work/init.sh" planted.example >"$work/first.log" 2>&1 || outcome=1
    for user in schema ingest reader metrics; do
        names+=("clickhouse_${user}_password")
    done
    for name in "${names[@]}"; do
        cp -p "$work/secrets/$name" "$work/good"
        planted_list=("${plants[0]}")
        if [[ "$name" == nats_gateway_password || "$name" == clickhouse_schema_password ]]; then
            planted_list=("${plants[@]}")
        fi
        for plant in "${planted_list[@]}"; do
            printf '%s' "$plant" >"$work/secrets/$name"
            rm -f "$work/secrets/nats.conf" "$work/secrets/clickhouse_users"
            ! "$work/init.sh" planted.example >"$work/planted.log" 2>&1 || outcome=1
            grep -q "error: .*/secrets/$name is not the 44 base64 characters" "$work/planted.log" || outcome=1
            ! grep -qF -e "${plant:0:20}" "$work/planted.log" || outcome=1
            [[ ! -e "$work/secrets/clickhouse_users" ]] || outcome=1
            [[ "$name" == clickhouse_* || ! -e "$work/secrets/nats.conf" ]] || outcome=1
        done
        printf '%s\0%s' AAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAA >"$work/secrets/$name"
        [[ "$name" != nats_admin_password && "$name" != clickhouse_reader_password ]] || ! "$work/init.sh" planted.example >"$work/planted.log" 2>&1 || outcome=1
        cp "$work/good" "$work/secrets/$name"
    done
    "$work/init.sh" planted.example >"$work/last.log" 2>&1 || outcome=1
    rm -rf "$work"
    [[ "$outcome" -eq 0 ]]
}

mark_refuses_planted_password() {
    local good=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= bad='x",permissions:{publish:">"}},{user:q,pass:"'
    ! ADMIN_PASSWORD="$good" GATEWAY_PASSWORD="$bad" SIEM_PASSWORD="$good" METRICS_PASSWORD="$good" "$TESTS_DIR/mark-nats-passwords.sh" </dev/null >/dev/null 2>&1 \
        && ADMIN_PASSWORD="$good" GATEWAY_PASSWORD="$good" SIEM_PASSWORD="$good" METRICS_PASSWORD="$good" "$TESTS_DIR/mark-nats-passwords.sh" </dev/null >/dev/null 2>&1
}

clickhouse_has() {
    clickhouse_service | grep -q -- "$1"
}

chschema_has() {
    chschema_service | grep -q -- "$1"
}

clickhouse_is_hardened() {
    clickhouse_has '^    read_only: true$' && clickhouse_has '^    cap_drop: \[ALL\]$' && clickhouse_has 'no-new-privileges:true' \
        && clickhouse_has '^    user: 101:101$' \
        && clickhouse_has '^    image: clickhouse/clickhouse-server:26.8.46@sha256:[0-9a-f]\{64\}$' \
        && clickhouse_has '^    secrets: \[clickhouse_server_key, clickhouse_server_cert, clickhouse_users\]$' \
        && clickhouse_has '^    command: \["clickhouse-server", "--config-file=/etc/clickhouse-server/ostyr-config.xml"\]$' \
        && ! clickhouse_has '^    ports:' && ! clickhouse_has 'cap_add' && ! clickhouse_has 'store_key' && ! clickhouse_has 'pg_service_password' \
        && ! clickhouse_has 'pg_ca' && ! clickhouse_has 'network_mode' && ! clickhouse_has 'schema_password'
}

chschema_is_hardened() {
    chschema_has '^    read_only: true$' && chschema_has '^    cap_drop: \[ALL\]$' && chschema_has 'no-new-privileges:true' \
        && chschema_has '^    user: 65530:65530$' && chschema_has '^    restart: on-failure:5$' \
        && chschema_has '^    image: clickhouse/clickhouse-server:26.8.46@sha256:[0-9a-f]\{64\}$' \
        && chschema_has '^    secrets: \[pg_ca, clickhouse_schema_password\]$' \
        && chschema_has '^    command: \["/bin/bash", "/etc/ostyr-schema/apply.sh"\]$' \
        && ! chschema_has '^    ports:' && ! chschema_has 'cap_add' && ! chschema_has 'clickhouse_users' && ! chschema_has 'clickhouse_server' \
        && ! chschema_has 'network_mode'
}

clickhouse_one_image() {
    [[ "$(grep '^    image: clickhouse/' "$COMPOSE_FILE" | sort -u | wc -l)" -eq 1 ]]
}

clickhouse_config_has() {
    grep -qxF -- "$1" "$CH_CONFIG_FILE"
}

clickhouse_serves_https_only() {
    clickhouse_config_has '    <https_port>8443</https_port>' && ! grep -q -e 'http_port' -e 'tcp_port' -e 'mysql_port' -e 'postgresql_port' -e 'interserver' \
        -e 'grpc' -e 'prometheus' "$CH_CONFIG_FILE" \
        && clickhouse_config_has '            <verificationMode>none</verificationMode>' && clickhouse_config_has '            <loadDefaultCAFile>false</loadDefaultCAFile>' \
        && clickhouse_config_has '            <certificateFile>/run/secrets/clickhouse_server_cert</certificateFile>' \
        && clickhouse_config_has '            <privateKeyFile>/run/secrets/clickhouse_server_key</privateKeyFile>' \
        && clickhouse_config_has '            <path>/run/secrets/clickhouse_users</path>'
}

clickhouse_is_bounded() {
    clickhouse_config_has '    <max_server_memory_usage>2147483648</max_server_memory_usage>' \
        && clickhouse_config_has '                <keep_free_space_bytes>2147483648</keep_free_space_bytes>'
}

clickhouse_users_are_least_privilege() {
    local users
    users="$(sed -n '/^<clickhouse>$/,/^<\/clickhouse>$/p' "$CH_INIT_FILE")"
    ! grep -q -e '<default>' -e 'access_management' -e 'GRANT ALL' -e '<password></password>' -e '<password>' -e 'no_password' -e '::/0' -e '0.0.0.0/0' <<<"$users" \
        && grep -qF '<readonly>2</readonly>' <<<"$users" && [[ "$(grep -c '<password_sha256_hex>' <<<"$users")" -eq 4 ]] \
        && [[ "$(grep -c '<networks><ip>$CLICKHOUSE_SUBNET</ip></networks>' <<<"$users")" -eq 4 ]] \
        && grep -qF 'readonly CLICKHOUSE_SUBNET=172.29.63.0/24' "$CH_INIT_FILE" \
        && grep -qF '<query>GRANT SELECT ON $CLICKHOUSE_DATABASE.*</query>' <<<"$users" \
        && grep -qF '<query>GRANT INSERT ON $CLICKHOUSE_DATABASE.events</query>' <<<"$users" \
        && grep -qF '<query>GRANT INSERT ON $CLICKHOUSE_DATABASE.metric_samples</query>' <<<"$users" \
        && [[ "$(grep -o 'GRANT ' <<<"$users" | wc -l)" -eq 4 ]] \
        && grep -qF 'GRANT CREATE DATABASE, CREATE TABLE, CREATE VIEW, SELECT, INSERT ON $CLICKHOUSE_DATABASE.*' <<<"$users"
}

clickhouse_schema_is_idempotent() {
    ! grep '^CREATE ' "$CH_SCHEMA_FILE" | grep -q -v 'IF NOT EXISTS' && grep -q '^CREATE TABLE IF NOT EXISTS `events`$' "$CH_SCHEMA_FILE"
}

clickhouse_views_run_as_schema() {
    [[ "$(grep -c '^CREATE MATERIALIZED VIEW ' "$CH_SCHEMA_FILE")" -eq 3 \
        && "$(grep -c '^CREATE MATERIALIZED VIEW .* DEFINER = schema SQL SECURITY DEFINER AS$' "$CH_SCHEMA_FILE")" -eq 3 ]]
}

clickhouse_serves_no_web_page() {
    [[ "$(grep -c '<url>' "$CH_CONFIG_FILE")" -eq 2 ]] && clickhouse_config_has '            <url>/ping</url>' && clickhouse_config_has '            <url>/</url>' \
        && ! grep -q -e '<defaults' -e 'play' -e 'dashboard' -e 'binary' -e 'js' "$CH_CONFIG_FILE"
}

clickhouse_init_refuses_other_users() {
    grep -qF 'if ! cmp -s "$SECRETS_DIR/$name" "$temporary"; then' "$CH_INIT_FILE" \
        && grep -qF 'is not the file init.sh renders from the four password files' "$CH_INIT_FILE"
}

nats_has() {
    nats_service | grep -q -- "$1"
}

gateway_has() {
    gateway_service | grep -q -- "$1"
}

relay_has() {
    relay_service | grep -q -- "$1"
}

nats_is_hardened() {
    nats_has '^    read_only: true$' && nats_has '^    cap_drop: \[ALL\]$' && nats_has 'no-new-privileges:true' \
        && nats_has '^    secrets: \[nats_conf, nats_server_key, nats_server_cert\]$' \
        && nats_has '^    command: \["--config", "/run/secrets/nats_conf"\]$' \
        && nats_has '^    image: nats:2.15.2-scratch@sha256:[0-9a-f]\{64\}$' \
        && ! nats_has '^    ports:' && ! nats_has 'cap_add' && ! nats_has 'store_key' && ! nats_has 'gateway_tls_key' && ! nats_has 'nats_gateway_password' \
        && ! nats_has 'network_mode'
}

gateway_is_hardened() {
    gateway_has '^    read_only: true$' && gateway_has '^    cap_drop: \[ALL\]$' && gateway_has 'no-new-privileges:true' \
        && gateway_has '^    user: 65534:65534$' \
        && gateway_has '^    secrets: \[pg_ca, gateway_tls_key, gateway_tls_cert, agent_ca, nats_gateway_password\]$' \
        && gateway_has '^    command: \["/usr/local/bin/ostyr-event-gateway", "/etc/ostyr/gateway-server.yaml", "/etc/ostyr/gateway.yaml"\]$' \
        && gateway_has '^        ipv4_address: 172.29.63.11$' && gateway_has '^      RUST_LOG: info$' \
        && ! gateway_has '^    ports:' && ! gateway_has 'cap_add' && ! gateway_has 'store_key' && ! gateway_has 'pg_service_password' \
        && ! gateway_has 'nats_conf' && ! gateway_has 'api_tls'
}

relay_is_hardened() {
    relay_has '^    read_only: true$' && relay_has '^    cap_drop: \[ALL\]$' && relay_has 'no-new-privileges:true' \
        && relay_has '^    user: 65531:65531$' \
        && relay_has '^    command: \["/usr/local/bin/ostyr-relay", "/etc/ostyr/relay.yaml", "/var/lib/ostyr-relay/relay-audit.log"\]$' \
        && relay_has '^        ipv4_address: 172.29.63.12$' \
        && ! relay_has '^    secrets:' && ! relay_has 'cap_add'
}

gateway_volume_items() {
    gateway_service | awk '/^    volumes:$/ {inside = 1; next} inside && /^      - / {print; next} {inside = 0}'
}

relay_volume_items() {
    relay_service | awk '/^    volumes:$/ {inside = 1; next} inside && /^      - / {print; next} {inside = 0}'
}

nats_volume_items() {
    nats_service | awk '/^    volumes:$/ {inside = 1; next} inside && /^      - / {print; next} {inside = 0}'
}

agent_path_mounts_only_its_volumes() {
    [[ "$(nats_volume_items)" == '      - natsdata:/data' \
        && "$(gateway_volume_items)" == '      - ./config:/etc/ostyr:ro'$'\n''      - gatewaystate:/var/lib/ostyr-gateway' \
        && "$(relay_volume_items)" == '      - ./config:/etc/ostyr:ro'$'\n''      - relaystate:/var/lib/ostyr-relay' ]]
}

only_the_relay_publishes_the_agent_port() {
    [[ "$(service_items relay ports)" == '      - "0.0.0.0:7443:7443"' ]] && ! service_has_key nats ports && ! service_has_key gateway ports
}

agent_path_addresses_agree() {
    local gateway_address relay_address
    gateway_address="$(sed -n 's/^        ipv4_address: //p' < <(gateway_service))"
    relay_address="$(sed -n 's/^        ipv4_address: //p' < <(relay_service))"
    grep -qx "relay_listen: \"$gateway_address:7443\"" "$COMPOSE_DIR/config/gateway-server.yaml" \
        && grep -qx "upstream: \"$gateway_address:7443\"" "$COMPOSE_DIR/config/relay.yaml" \
        && grep -qx 'listen: "0.0.0.0:7443"' "$COMPOSE_DIR/config/relay.yaml" \
        && grep -qx "relay_sources: \[$relay_address\]" "$COMPOSE_DIR/config/channel-settings.yaml" \
        && grep -qx 'listen: "127.0.0.1:7444"' "$COMPOSE_DIR/config/gateway-server.yaml"
}

gateway_files_use_only_its_secrets_and_state() {
    ! grep -n -e '/run/secrets/' "$COMPOSE_DIR/config/gateway-server.yaml" "$COMPOSE_DIR/config/gateway-settings.yaml" \
        | grep -v -e '/run/secrets/gateway_tls_cert$' -e '/run/secrets/gateway_tls_key$' -e '/run/secrets/agent_ca$' -e '/run/secrets/pg_ca$' \
            -e '/run/secrets/nats_gateway_password$' \
        && ! grep -h -e '^[a-z_]*file: /var/lib\|^commands_dir: ' "$COMPOSE_DIR/config/gateway-server.yaml" "$COMPOSE_DIR/config/gateway.yaml" \
        | grep -v ': /var/lib/ostyr-gateway/'
}

playbooks_has() {
    playbooks_service | grep -q -- "$1"
}

playbooks_is_hardened() {
    playbooks_has '^    read_only: true$' && playbooks_has '^    cap_drop: \[ALL\]$' && playbooks_has 'no-new-privileges:true' \
        && playbooks_has '^    user: 65533:65533$' && playbooks_has '^    secrets: \[playbooks_pg_password, pg_ca\]$' \
        && playbooks_has '^    command: \["/usr/local/bin/ostyr-playbooks", "/etc/ostyr/playbooks.yaml"\]$' \
        && ! playbooks_has '^    ports:' && ! playbooks_has 'cap_add' && ! playbooks_has 'store_key' && ! playbooks_has 'pg_service_password'
}

playbooks_volume_items() {
    playbooks_service | awk '/^    volumes:$/ {inside = 1; next} inside && /^      - / {print; next} {inside = 0}'
}

playbooks_mounts_only_settings_and_its_state() {
    [[ "$(playbooks_volume_items)" == '      - ./config:/etc/ostyr:ro'$'\n''      - playbooksstate:/var/lib/ostyr-playbooks' ]]
}

web_volume_items() {
    web_service | awk '/^    volumes:$/ {inside = 1; next} inside && /^      - / {print; next} {inside = 0}'
}

web_mounts_only_settings_and_state() {
    [[ "$(web_volume_items)" == '      - ./config:/etc/ostyr:ro'$'\n''      - webstate:/var/lib/ostyr' ]]
}

block_scalar_lines() {
    printf '%s\n' '      - |' \
        '        install -d -m 0700 -o postgres -g postgres /run/pgtls' \
        '        install -m 0600 -o postgres -g postgres /run/secrets/pg_service_password /run/pgtls/service_password' \
        '        install -m 0600 -o postgres -g postgres /run/secrets/pg_server_key /run/pgtls/server.key' \
        '        install -m 0644 -o postgres -g postgres /run/secrets/pg_server_cert /run/pgtls/server.crt' \
        '        exec docker-entrypoint.sh "$$@"'
}

unknown_shapes() {
    LC_ALL=C grep -v -x -F -f <(block_scalar_lines) "$COMPOSE_FILE" | LC_ALL=C awk -v keys="$ALLOWED_KEYS" -v flow="$FLOW_KEYS" -v blocks="$BLOCK_KEYS" '
        function key_line(text,    key, value) {
            if (!match(text, /^[A-Za-z_][A-Za-z0-9_]*:/)) {return 0}
            key = substr(text, 1, RLENGTH - 1)
            value = substr(text, RLENGTH + 1)
            if (!(key in allowed)) {return 0}
            if (value == "") {return 1}
            if ((key in block) || value !~ /^ [^ ]/) {return 0}
            value = substr(value, 2)
            if (value ~ /^\[/) {return key in flowing}
            return value == "{}" || value !~ /^[\[{&*!|>%@`"\047?-]/
        }
        function item_at_parent_indent(current, indent,    j) {
            for (j = current - 1; j > 0; j--) {
                if (line_indent[j] <= indent) {return !line_is_item[j] && line_indent[j] == indent}
            }
            return 0
        }
        BEGIN {
            split(keys, a, " "); for (i in a) {allowed[a[i]] = 1}
            split(flow, b, " "); for (i in b) {flowing[b[i]] = 1}
            split(blocks, c, " "); for (i in c) {block[c[i]] = 1}
        }
        {
            body = $0
            sub(/^ */, "", body)
            indent = length($0) - length(body)
            lines_seen++
            line_indent[lines_seen] = indent
            line_is_item[lines_seen] = (body ~ /^- /)
            if ($0 !~ /^[ -~]*$/ || body == "") {print; next}
            if (body ~ /^- /) {
                if (item_at_parent_indent(lines_seen, indent)) {print; next}
                body = substr(body, 3)
                if (body !~ /^([A-Za-z0-9_\/."]|-[A-Za-z])/ || body ~ /:$/) {print; next}
                if (body !~ /^[A-Za-z_][A-Za-z0-9_]*: /) {next}
            }
            if (!key_line(body)) {print}
        }'
}

shapes_are_allowed() {
    ! unknown_shapes | grep -q .
}

stray_compose_inputs() {
    find "$PROJECT_DIR" -maxdepth 1 \( -name 'compose*.y*ml' -o -name 'docker-compose*' -o -name '.env*' \) ! -name compose.yaml
}

entrypoint_block_in_place() {
    [[ "$(grep -c -x -F -f <(block_scalar_lines) "$COMPOSE_FILE")" -eq "$(block_scalar_lines | wc -l)" && "$(grep -c -x -F -- '      - -ec' "$COMPOSE_FILE")" -eq 1 \
        && "$(grep -x -F -A "$(block_scalar_lines | wc -l)" -- '      - -ec' "$COMPOSE_FILE" | tail -n +2)" == "$(block_scalar_lines)" ]]
}

no_other_compose_input() {
    ! stray_compose_inputs | grep -q .
}

dollar_outside_entrypoint() {
    LC_ALL=C grep -v -x -F -f <(block_scalar_lines) "$COMPOSE_FILE" | grep -q -F '$'
}

no_interpolation() {
    ! dollar_outside_entrypoint
}

outside_allowlist() {
    LC_ALL=C grep -a -v -x -F -f <(block_scalar_lines) "$COMPOSE_FILE" | LC_ALL=C sed 's/: {}$/:/' \
        | LC_ALL=C grep -a -v -x '[]A-Za-z0-9 _./:=,"'"'"'@[-]*'
}

only_allowlisted_bytes() {
    ! outside_allowlist | grep -q .
}

no_backslash() {
    ! LC_ALL=C grep -a -q -F '\' "$COMPOSE_FILE"
}

environment_valueless_items() {
    LC_ALL=C awk '/^ *environment:/ {match($0, /^ */); base = RLENGTH; inside = 1; next}
        inside {match($0, /^ */); if (RLENGTH <= base) {inside = 0}}
        inside {
            item = $0
            sub(/^ */, "", item)
            sub(/ *$/, "", item)
            if (item ~ /^- /) {if (item !~ /^- [A-Za-z_][A-Za-z0-9_]*=/) {print}; next}
            if (item !~ /^[A-Za-z_][A-Za-z0-9_]*: +[^ ]/ || item ~ /: +(~|[Nn]ull|NULL)$/) {print}
        }' "$COMPOSE_FILE"
}

no_environment_passthrough() {
    ! environment_valueless_items | grep -q .
}

published_port_items() {
    awk '/^ *ports:/ {match($0, /^ */); base = RLENGTH; inside = 1; next}
        inside {match($0, /^ */); if (RLENGTH < base || (RLENGTH == base && $0 !~ /^ *- /)) {inside = 0}}
        inside && /^ *- / {sub(/^ */, ""); print}' "$COMPOSE_FILE"
}

only_the_three_ports_are_published() {
    [[ "$(published_port_items)" == '- "0.0.0.0:8443:8443"'$'\n''- "0.0.0.0:9443:9443"'$'\n''- "0.0.0.0:7443:7443"' ]] && ! grep -q '^ *ports:.' "$COMPOSE_FILE"
}

service_items() {
    awk -v name="$1" -v key="    $2:" '$0 == "  " name ":" {inside = 1; next} /^  [^ ]/ || /^[^ ]/ {inside = 0; found = 0}
        inside && $0 == key {found = 1; next} inside && found && /^      - / {print; next} {found = 0}' "$COMPOSE_FILE"
}

service_has_key() {
    awk -v name="$1" -v key="    $2:" '$0 == "  " name ":" {inside = 1; next} /^  [^ ]/ || /^[^ ]/ {inside = 0} inside && index($0, key) == 1 {found = 1} END {exit !found}' "$COMPOSE_FILE"
}

each_service_publishes_only_its_port() {
    [[ "$(service_items platform ports)" == '      - "0.0.0.0:8443:8443"' && "$(service_items web ports)" == '      - "0.0.0.0:9443:9443"' ]] \
        && ! service_has_key postgres ports && ! service_has_key playbooks ports
}

every_service_mounts_only_its_volumes() {
    [[ "$(service_items postgres volumes)" == '      - pgdata:/var/lib/postgresql/data'$'\n''      - ./config/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro'$'\n''      - ./config/pg-init-service-role.sh:/docker-entrypoint-initdb.d/10-service-role.sh:ro' \
        && "$(service_items platform volumes)" == '      - ./config:/etc/ostyr:ro'$'\n''      - state:/var/lib/ostyr' ]] && web_mounts_only_settings_and_state \
        && playbooks_mounts_only_settings_and_its_state && agent_path_mounts_only_its_volumes && clickhouse_mounts_only_its_volumes \
        && [[ "$(service_items siem volumes)" == '      - ./config:/etc/ostyr:ro'$'\n''      - siemstate:/var/lib/ostyr-siem' ]] \
        && [[ "$(service_items metrics volumes)" == '      - ./config:/etc/ostyr:ro'$'\n''      - metricsstate:/var/lib/ostyr-metrics' ]] \
        && [[ "$(service_items metricalerts volumes)" == '      - ./config:/etc/ostyr:ro'$'\n''      - alertsstate:/var/lib/ostyr-metric-alerts' ]]
}

clickhouse_mounts_only_its_volumes() {
    [[ "$(service_items clickhouse volumes)" == '      - chdata:/var/lib/clickhouse'$'\n''      - ./config/clickhouse-config.xml:/etc/clickhouse-server/ostyr-config.xml:ro' \
        && "$(service_items chschema volumes)" == '      - ./config/clickhouse-apply.sh:/etc/ostyr-schema/apply.sh:ro'$'\n''      - ./config/clickhouse-schema.sql:/etc/ostyr-schema/schema.sql:ro' ]]
}

only_postgres_adds_capabilities() {
    ! service_has_key siem cap_add && ! service_has_key metrics cap_add && ! service_has_key metricalerts cap_add && ! service_has_key siem ports && ! service_has_key metrics ports \
        && ! service_has_key metricalerts ports && only_postgres_adds_capabilities_listed
}

only_postgres_adds_capabilities_listed() {
    [[ "$(count_lines 'cap_add')" -eq 1 ]] && service_has_key postgres cap_add && ! service_has_key platform cap_add && ! service_has_key web cap_add && ! service_has_key playbooks cap_add \
        && ! service_has_key nats cap_add && ! service_has_key gateway cap_add && ! service_has_key relay cap_add \
        && ! service_has_key clickhouse cap_add && ! service_has_key chschema cap_add
}

definitions_are_pinned() {
    local expected
    expected="$(printf '%s\n' 'volumes:' '  pgdata: {}' '  state: {}' '  webstate: {}' '  playbooksstate: {}' '  natsdata: {}' '  gatewaystate: {}' '  relaystate: {}' '  chdata: {}' '  siemstate: {}' '  metricsstate: {}' '  alertsstate: {}' 'secrets:' \
        '  pg_password:' '    file: ./secrets/pg_password' '  pg_service_password:' '    file: ./secrets/pg_service_password' \
        '  pg_server_key:' '    file: ./secrets/pg_server.key' '  pg_server_cert:' '    file: ./secrets/pg_server.crt' \
        '  pg_ca:' '    file: ./secrets/ca.crt' '  playbooks_pg_password:' '    file: ./secrets/playbooks_pg_password' '  api_tls_key:' '    file: ./secrets/api_tls.key' '  api_tls_cert:' '    file: ./secrets/api_tls.crt' \
        '  store_key:' '    file: ./secrets/store.key' '  gateway_tls_key:' '    file: ./secrets/gateway_tls.key' '  gateway_tls_cert:' '    file: ./secrets/gateway_tls.crt' \
        '  nats_server_key:' '    file: ./secrets/nats_server.key' '  nats_server_cert:' '    file: ./secrets/nats_server.crt' '  nats_conf:' '    file: ./secrets/nats.conf' \
        '  agent_ca:' '    file: ./secrets/agent_ca.crt' '  nats_gateway_password:' '    file: ./secrets/nats_gateway_password' \
        '  clickhouse_server_key:' '    file: ./secrets/clickhouse_server.key' '  clickhouse_server_cert:' '    file: ./secrets/clickhouse_server.crt' \
        '  clickhouse_users:' '    file: ./secrets/clickhouse_users' '  clickhouse_schema_password:' '    file: ./secrets/clickhouse_schema_password' \
        '  clickhouse_ingest_password:' '    file: ./secrets/clickhouse_ingest_password' '  clickhouse_metrics_password:' '    file: ./secrets/clickhouse_metrics_password' \
        '  nats_siem_password:' '    file: ./secrets/nats_siem_password' '  nats_metrics_password:' '    file: ./secrets/nats_metrics_password' \
        '  metricalerts_pg_password:' '    file: ./secrets/metricalerts_pg_password' '  metricalerts_clickhouse_password:' '    file: ./secrets/metricalerts_clickhouse_password')"
    [[ "$(sed -n '/^volumes:$/,$p' "$COMPOSE_FILE")" == "$expected" && "$(count_lines '^ *name:')" -eq 1 && "$(count_lines '^name: ostyr$')" -eq 1 ]]
}

compose_service_names() {
    sed -n '/^services:$/,/^[a-z]/{s/^  \([A-Za-z_][A-Za-z0-9_]*\):$/\1/p}' "$COMPOSE_FILE" | sort | tr '\n' ' '
}

init_service_names() {
    sed -n 's/^readonly SERVICE_NAMES=(\(.*\))$/\1/p' "$CH_INIT_FILE" | tr ' ' '\n' | sort | tr '\n' ' '
}

init_lists_compose_services() {
    [[ -n "$(compose_service_names)" && "$(compose_service_names)" == "$(init_service_names)" ]]
}

san_extension_der() {
    local body="" name hex
    for name in "$@"; do
        hex="$(printf '%s' "$name" | od -An -tx1 | tr -d ' \n')"
        body+="$(printf '82%02x%s' $((${#hex} / 2)) "$hex")"
    done
    printf '30%02x%s' $((${#body} / 2)) "$body"
}

make_san_certificate() {
    local output="$1" extension="$2"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /dev/null -out "$output" -subj /CN=gateway -addext "subjectAltName=$extension" 2>/dev/null
}

run_init_function() {
    local functions="$1" secrets="$2" before
    shift 2
    before="$(sha256sum "$secrets"/*)"
    (
        SECRETS_DIR="$secrets"
        TLS_FILES=(a b)
        export SECRETS_DIR TLS_FILES
        # shellcheck source=/dev/null
        source "$functions"
        "$@"
    ) 2>&1
    [[ "$(sha256sum "$secrets"/*)" == "$before" ]] || printf 'CHANGED a file of %s\n' "$secrets"
}

init_warnings_behave() {
    local work secrets name outcome=0
    mkdir -p "$COMPOSE_DIR/../../target"
    work="$(mktemp -d "$COMPOSE_DIR/../../target/init-warnings.XXXXXX")"
    secrets="$work/secrets"
    mkdir "$secrets"
    sed -n '/^warn_gateway_san() {/,/^}/p' "$CH_INIT_FILE" >"$work/functions.sh"
    make_san_certificate "$work/good.crt" DNS:gateway
    make_san_certificate "$work/extra.crt" DNS:gateway,DNS:platform
    make_san_certificate "$work/newline.crt" "DER:$(san_extension_der $'gateway\nSubject Alternative Name' platform)"
    cp "$work/good.crt" "$secrets/gateway_tls.crt"
    [[ -z "$(run_init_function "$work/functions.sh" "$secrets" warn_gateway_san)" ]] || outcome=1
    for name in extra newline; do
        cp "$work/$name.crt" "$secrets/gateway_tls.crt"
        run_init_function "$work/functions.sh" "$secrets" warn_gateway_san | grep -q 'gateway_tls.crt names more than DNS:gateway' || outcome=1
        run_init_function "$work/functions.sh" "$secrets" warn_gateway_san | grep -q CHANGED && outcome=1
    done
    rm -rf "$work"
    [[ "$outcome" -eq 0 ]]
}

init_warns_on_old_files() {
    grep -qF 'gateway_tls.crt names more than DNS:gateway' "$CH_INIT_FILE"
}

web_has() {
    web_service | grep -q -- "$1"
}

web_is_hardened() {
    web_has '^    read_only: true$' && web_has '^    cap_drop: \[ALL\]$' && web_has 'no-new-privileges:true' \
        && web_has '^    secrets: \[pg_ca, api_tls_key, api_tls_cert\]$' && web_has '^      - "0.0.0.0:9443:9443"$'
}

web_lacks() {
    ! web_has "$1"
}

web_yaml_has() {
    grep -qx -- "$1" "$COMPOSE_DIR/config/web-ui.yaml"
}

web_yaml_serves_tls_and_verifies_api() {
    web_yaml_has 'tls:' && web_yaml_has '  certificate: /run/secrets/api_tls_cert' && web_yaml_has '  key: /run/secrets/api_tls_key' \
        && web_yaml_has 'api:' && web_yaml_has '  base_url: https://platform:8443' && web_yaml_has '  ca: /run/secrets/pg_ca'
}

compose_config_accepts() {
    local scratch name
    scratch="$(mktemp -d "$COMPOSE_DIR/../../target/compose-static.XXXXXX")"
    mkdir -p "$scratch/secrets"
    for name in pg_password pg_service_password pg_server.key pg_server.crt ca.crt api_tls.key api_tls.crt store.key playbooks_pg_password gateway_tls.key gateway_tls.crt nats_server.key nats_server.crt nats.conf agent_ca.crt nats_gateway_password clickhouse_server.key clickhouse_server.crt clickhouse_users clickhouse_schema_password clickhouse_ingest_password clickhouse_metrics_password nats_siem_password nats_metrics_password metricalerts_pg_password metricalerts_clickhouse_password; do
        : >"$scratch/secrets/$name"
    done
    cp -r "$COMPOSE_DIR/config" "$scratch/"
    cp "$COMPOSE_FILE" "$scratch/compose.yaml"
    docker compose --profile "*" -f "$scratch/compose.yaml" config -q
    rm -rf "$scratch"
}

parsed_config_passes() {
    local scratch name status=0
    scratch="$(mktemp -d "$COMPOSE_DIR/../../target/compose-static.XXXXXX")"
    mkdir -p "$scratch/secrets"
    for name in pg_password pg_service_password pg_server.key pg_server.crt ca.crt api_tls.key api_tls.crt store.key playbooks_pg_password gateway_tls.key gateway_tls.crt nats_server.key nats_server.crt nats.conf agent_ca.crt nats_gateway_password clickhouse_server.key clickhouse_server.crt clickhouse_users clickhouse_schema_password clickhouse_ingest_password clickhouse_metrics_password nats_siem_password nats_metrics_password metricalerts_pg_password metricalerts_clickhouse_password; do
        : >"$scratch/secrets/$name"
    done
    cp -r "$COMPOSE_DIR/config" "$scratch/"
    cp "$COMPOSE_FILE" "$scratch/compose.yaml"
    docker compose --profile "*" -f "$scratch/compose.yaml" config --format json | python3 -I "$TESTS_DIR/config-check.py" "$scratch" "$TESTS_DIR/expected-projection.json" || status=1
    rm -rf "$scratch"
    return "$status"
}

expect "compose.yaml uses only the allowed YAML shapes" shapes_are_allowed
expect "the entrypoint script lines appear once, right after its -ec line" entrypoint_block_in_place
expect "no other compose file or .env is in the project directory" no_other_compose_input
expect "compose.yaml interpolates no variable outside the entrypoint script" no_interpolation
expect "compose.yaml holds only allowlisted characters outside the entrypoint" only_allowlisted_bytes
expect "compose.yaml holds no backslash escape" no_backslash
expect "compose.yaml has no environment entry without a value" no_environment_passthrough
if [[ "$failures" -ne 0 ]]; then
    unknown_shapes | head -n 5 >&2
    printf 'an early check failed: nothing else was checked\n' >&2
    exit 1
fi

if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    mkdir -p "$COMPOSE_DIR/../../target"
    expect "docker compose config accepts compose.yaml" compose_config_accepts
    expect "the parsed configuration equals the committed projection" parsed_config_passes
else
    printf 'info docker compose is NOT installed on this host: the compose config check was SKIPPED\n'
fi
if command -v shellcheck >/dev/null; then
    expect "shellcheck accepts the scripts" shellcheck --severity=warning "$COMPOSE_DIR/init.sh" "$COMPOSE_DIR/build.sh" "$COMPOSE_DIR/config/pg-init-service-role.sh" "$COMPOSE_DIR/config/clickhouse-apply.sh" "$TESTS_DIR/static-test.sh" "$TESTS_DIR/compose-lab.sh" "$TESTS_DIR/pg-proofs.sh" "$TESTS_DIR/stage-file-test.sh" "$TESTS_DIR/web-proof.sh" "$TESTS_DIR/module-proof.sh" "$TESTS_DIR/agent-proof.sh" "$TESTS_DIR/lab-accounts.sh" "$TESTS_DIR/clickhouse-proof.sh" "$TESTS_DIR/ingest-proof.sh" "$TESTS_DIR/mutation-test.sh"
else
    printf 'info shellcheck is not installed: skipped\n'
fi

expect "no PostgreSQL port is published" absent grep -e '5432' "$COMPOSE_FILE"
expect "only the API, web and relay ports are published, in any syntax" only_the_three_ports_are_published
expect "the web service mounts exactly its settings directory and its state volume" web_mounts_only_settings_and_state
expect "the platform publishes 8443, web 9443 and postgres nothing" each_service_publishes_only_its_port
expect "only the relay publishes 7443; nats and the gateway publish nothing" only_the_relay_publishes_the_agent_port
expect "every service mounts only its own volumes and binds" every_service_mounts_only_its_volumes
expect "only postgres adds capabilities" only_postgres_adds_capabilities
expect "the volume and secret definitions are exactly the expected ones" definitions_are_pinned
expect "the web service is hardened, publishes 9443 and holds three secrets" web_is_hardened
for refused_secret in pg_password pg_service_password pg_server store_key; do
    expect "the web service holds no $refused_secret secret" web_lacks "$refused_secret"
done
expect "the web service runs ostyr-web-ui on its own settings file" web_has 'command: \["/usr/local/bin/ostyr-web-ui", "/etc/ostyr/web-ui.yaml"\]'
expect "the platform trusts the web address only as forwarder" grep -qx '  trusted_forwarders: 172.29.63.10' "$COMPOSE_DIR/config/module.yaml"
expect "the module file selects all fifteen modules the platform mounts" grep -qx '  modules: alerts, cases, cmdb, risk, hunts, certificates, oncall, dhcp, compliance, vulnerabilities, remote_shell, posture, status, grc, attack_paths' "$COMPOSE_DIR/config/module.yaml"
expect "the module file names the status page file" grep -qx '  status.page_file: /etc/ostyr/status-page.yaml' "$COMPOSE_DIR/config/module.yaml"
expect "the status page belongs to the module file tenant" test "$(sed -n 's/^tenant: //p' "$COMPOSE_DIR/config/status-page.yaml")" = "$(sed -n 's/^tenant: //p' "$COMPOSE_DIR/config/module.yaml")"
expect "the playbooks service is hardened, runs as 65533 and holds only its password copy and the CA" playbooks_is_hardened
expect "init.sh compares an existing password copy with its source and refuses a difference by name" \
    grep -qF 'cmp -s "$SECRETS_DIR/$name" "$SECRETS_DIR/$source"' "$COMPOSE_DIR/init.sh"
expect "the playbooks service reads the compose tenant" test "$(sed -n 's/^tenant: //p' "$COMPOSE_DIR/config/playbooks.yaml")" = "$(sed -n 's/^tenant: //p' "$COMPOSE_DIR/config/module.yaml")"
expect "the playbooks database settings name its own password file" grep -qx 'password_file: /run/secrets/playbooks_pg_password' "$COMPOSE_DIR/config/playbooks-pg.yaml"
expect "the nats service is hardened, pinned by digest, publishes no port and holds only its three secrets" nats_is_hardened
expect "the gateway service is hardened, runs as 65534 and holds only its five secrets" gateway_is_hardened
expect "the relay service is hardened, runs as 65531 and holds no secret" relay_is_hardened
expect "the gateway, relay and channel settings name the same addresses and ports" agent_path_addresses_agree
expect "the gateway files name only its own secrets and state" gateway_files_use_only_its_secrets_and_state
expect "the NATS user gateway publishes events.* only and subscribes to its own inbox" \
    grep -qF 'permissions: { publish: { allow: ["events.*"] }, subscribe: { allow: ["_INBOX_gateway.>"] } }' "$COMPOSE_DIR/init.sh"
expect "the gateway certificate names DNS:gateway only" grep -qF 'make_leaf gateway_tls ostyr-gateway DNS:gateway "$scratch"' "$CH_INIT_FILE"
expect "init.sh refuses every compose service name as the public host name" \
    grep -qF 'readonly SERVICE_NAMES=(postgres platform web playbooks nats gateway relay clickhouse chschema siem metrics metricalerts)' "$CH_INIT_FILE"
expect "init.sh lists exactly the services of compose.yaml" init_lists_compose_services
expect "init.sh warns by name about a gateway certificate with more names, and changes no file" init_warnings_behave
expect "init.sh warns by name about a gateway certificate with more names" init_warns_on_old_files
expect "the siem service is hardened, runs as 65529 and holds only the CA and its two passwords" siem_is_hardened
expect "the metrics service is hardened, runs as 65528 and holds only the CA and its two passwords" metrics_is_hardened
expect "the metricalerts service is hardened, runs as 65527 and holds only the CA and its two password copies" metricalerts_is_hardened
expect "the ingest settings files name only their own secrets and state directory" ingest_files_use_only_their_secrets
expect "the ingest settings files name their own ClickHouse and NATS users" ingest_files_use_their_own_clickhouse_user
expect "the NATS consumer accounts are scoped to one durable each and have no create or purge subject" nats_consumer_accounts_are_scoped
expect "the nats.conf written by the real init.sh equals the committed golden file" nats_conf_matches_golden
expect "init.sh refuses an existing nats.conf that is not its own rendering, by name" nats_init_refuses_other_conf
if [[ "${STATIC_TEST_SKIP_PLANTED:-0}" != 1 ]]; then
    expect "init.sh refuses a planted password file whose text is not the generated format, by name, and renders nothing" init_refuses_planted_secrets
fi
expect "mark-nats-passwords.sh refuses a password that is not the generated format" mark_refuses_planted_password
expect "the clickhouse service is hardened, pinned by digest, publishes no port and holds only its three secrets" clickhouse_is_hardened
expect "the chschema service is hardened, runs as 65530 and holds only the CA and its password" chschema_is_hardened
expect "both ClickHouse services use one pinned image" clickhouse_one_image
expect "ClickHouse serves HTTPS 8443 only, with its own certificate and users file" clickhouse_serves_https_only
expect "ClickHouse bounds its memory and keeps free disk space" clickhouse_is_bounded
expect "ClickHouse has no default user, four hashed users on the compose subnet and a readonly=2 reader" clickhouse_users_are_least_privilege
expect "the ClickHouse schema file creates every object with IF NOT EXISTS" clickhouse_schema_is_idempotent
expect "the ClickHouse materialised views run as schema, so the metrics writer needs no SELECT" clickhouse_views_run_as_schema
expect "ClickHouse answers only POST / and GET /ping, no web page" clickhouse_serves_no_web_page
expect "init.sh refuses a users file that differs from the rendered one" clickhouse_init_refuses_other_users
expect "the chschema service keeps its data and log directories on tmpfs" chschema_has '^      - /var/lib/clickhouse$'
expect "the ClickHouse certificate names DNS:clickhouse only" grep -qF 'make_leaf clickhouse_server clickhouse DNS:clickhouse "$scratch"' "$COMPOSE_DIR/init.sh"
expect "init.sh bounds the JetStream file store" grep -qF 'max_file_store: $NATS_MAX_FILE_STORE' "$COMPOSE_DIR/init.sh"
expect "the web address is pinned to that address" web_has 'ipv4_address: 172.29.63.10$'
expect "web-ui.yaml serves TLS and verifies the API against the CA" web_yaml_serves_tls_and_verifies_api
expect "every image is pinned by digest or built locally" images_are_pinned
expect "every service is read-only, drops capabilities and sets no-new-privileges" all_services_hardened
expect "no YAML file has a comment" absent grep -n '#' "$COMPOSE_FILE" "$COMPOSE_DIR"/config/*.yaml
expect "pg_hba accepts hostssl only" absent grep -E '^host ' "$COMPOSE_DIR/config/pg_hba.conf"
expect "the only local pg_hba line is the in-container socket" test "$(grep -c '^local ' "$COMPOSE_DIR/config/pg_hba.conf")" -eq 1
expect "pg_hba admits one role on one database" test "$(grep -c '^hostssl ostyr ostyr_service all scram-sha-256$' "$COMPOSE_DIR/config/pg_hba.conf")" -eq 1
expect "the platform does not log in as the superuser" absent grep -e 'user: postgres' -e 'pg_password' "$COMPOSE_DIR/config/pg.yaml"
expect "no image is named by a tag alone in the README" absent grep -E 'busybox( |$)' "$COMPOSE_DIR/README.md"
expect "secrets are ignored by Git" grep -qx 'secrets/' "$COMPOSE_DIR/.gitignore"
expect "no secret is written in an environment value" absent grep -E '^      [A-Z_]*(PASSWORD|KEY):' "$COMPOSE_FILE"

if [[ "$failures" -ne 0 ]]; then
    printf '%s check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'all checks passed\n'
