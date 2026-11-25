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
readonly PROJECT_DIR="${STATIC_TEST_PROJECT_DIR:-$COMPOSE_DIR}"
readonly ALLOWED_KEYS="name services postgres platform web image restart read_only cap_drop cap_add security_opt environment POSTGRES_PASSWORD_FILE entrypoint command secrets volumes tmpfs healthcheck test interval timeout retries pull_policy depends_on condition networks default ipv4_address ports ipam config subnet ip_range pgdata state webstate playbooks playbooksstate user file pg_password pg_service_password pg_server_key pg_server_cert pg_ca playbooks_pg_password api_tls_key api_tls_cert store_key nats gateway relay natsdata gatewaystate relaystate gateway_tls_key gateway_tls_cert nats_server_key nats_server_cert nats_conf agent_ca nats_gateway_password RUST_LOG clickhouse chschema chdata clickhouse_server_key clickhouse_server_cert clickhouse_users clickhouse_schema_password CLICKHOUSE_WATCHDOG_ENABLE"
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
        && playbooks_mounts_only_settings_and_its_state && agent_path_mounts_only_its_volumes && clickhouse_mounts_only_its_volumes
}

clickhouse_mounts_only_its_volumes() {
    [[ "$(service_items clickhouse volumes)" == '      - chdata:/var/lib/clickhouse'$'\n''      - ./config/clickhouse-config.xml:/etc/clickhouse-server/ostyr-config.xml:ro' \
        && "$(service_items chschema volumes)" == '      - ./config/clickhouse-apply.sh:/etc/ostyr-schema/apply.sh:ro'$'\n''      - ./config/clickhouse-schema.sql:/etc/ostyr-schema/schema.sql:ro' ]]
}

only_postgres_adds_capabilities() {
    [[ "$(count_lines 'cap_add')" -eq 1 ]] && service_has_key postgres cap_add && ! service_has_key platform cap_add && ! service_has_key web cap_add && ! service_has_key playbooks cap_add \
        && ! service_has_key nats cap_add && ! service_has_key gateway cap_add && ! service_has_key relay cap_add \
        && ! service_has_key clickhouse cap_add && ! service_has_key chschema cap_add
}

definitions_are_pinned() {
    local expected
    expected="$(printf '%s\n' 'volumes:' '  pgdata: {}' '  state: {}' '  webstate: {}' '  playbooksstate: {}' '  natsdata: {}' '  gatewaystate: {}' '  relaystate: {}' '  chdata: {}' 'secrets:' \
        '  pg_password:' '    file: ./secrets/pg_password' '  pg_service_password:' '    file: ./secrets/pg_service_password' \
        '  pg_server_key:' '    file: ./secrets/pg_server.key' '  pg_server_cert:' '    file: ./secrets/pg_server.crt' \
        '  pg_ca:' '    file: ./secrets/ca.crt' '  playbooks_pg_password:' '    file: ./secrets/playbooks_pg_password' '  api_tls_key:' '    file: ./secrets/api_tls.key' '  api_tls_cert:' '    file: ./secrets/api_tls.crt' \
        '  store_key:' '    file: ./secrets/store.key' '  gateway_tls_key:' '    file: ./secrets/gateway_tls.key' '  gateway_tls_cert:' '    file: ./secrets/gateway_tls.crt' \
        '  nats_server_key:' '    file: ./secrets/nats_server.key' '  nats_server_cert:' '    file: ./secrets/nats_server.crt' '  nats_conf:' '    file: ./secrets/nats.conf' \
        '  agent_ca:' '    file: ./secrets/agent_ca.crt' '  nats_gateway_password:' '    file: ./secrets/nats_gateway_password' \
        '  clickhouse_server_key:' '    file: ./secrets/clickhouse_server.key' '  clickhouse_server_cert:' '    file: ./secrets/clickhouse_server.crt' \
        '  clickhouse_users:' '    file: ./secrets/clickhouse_users' '  clickhouse_schema_password:' '    file: ./secrets/clickhouse_schema_password')"
    [[ "$(sed -n '/^volumes:$/,$p' "$COMPOSE_FILE")" == "$expected" && "$(count_lines '^ *name:')" -eq 1 && "$(count_lines '^name: ostyr$')" -eq 1 ]]
}

compose_service_names() {
    sed -n '/^services:$/,/^[a-z]/{s/^  \([a-z]*\):$/\1/p}' "$COMPOSE_FILE" | sort | tr '\n' ' '
}

init_service_names() {
    sed -n 's/^readonly SERVICE_NAMES=(\(.*\))$/\1/p' "$CH_INIT_FILE" | tr ' ' '\n' | sort | tr '\n' ' '
}

init_lists_compose_services() {
    [[ -n "$(compose_service_names)" && "$(compose_service_names)" == "$(init_service_names)" ]]
}

init_warns_on_old_files() {
    grep -qF "has no max_file_store, so JetStream may fill the disk" "$CH_INIT_FILE" && grep -qF 'gateway_tls.crt names more than DNS:gateway' "$CH_INIT_FILE"
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
    for name in pg_password pg_service_password pg_server.key pg_server.crt ca.crt api_tls.key api_tls.crt store.key playbooks_pg_password gateway_tls.key gateway_tls.crt nats_server.key nats_server.crt nats.conf agent_ca.crt nats_gateway_password clickhouse_server.key clickhouse_server.crt clickhouse_users clickhouse_schema_password; do
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
    for name in pg_password pg_service_password pg_server.key pg_server.crt ca.crt api_tls.key api_tls.crt store.key playbooks_pg_password gateway_tls.key gateway_tls.crt nats_server.key nats_server.crt nats.conf agent_ca.crt nats_gateway_password clickhouse_server.key clickhouse_server.crt clickhouse_users clickhouse_schema_password; do
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
    expect "shellcheck accepts the scripts" shellcheck --severity=warning "$COMPOSE_DIR/init.sh" "$COMPOSE_DIR/build.sh" "$COMPOSE_DIR/config/pg-init-service-role.sh" "$COMPOSE_DIR/config/clickhouse-apply.sh" "$TESTS_DIR/static-test.sh" "$TESTS_DIR/compose-lab.sh" "$TESTS_DIR/pg-proofs.sh" "$TESTS_DIR/stage-file-test.sh" "$TESTS_DIR/web-proof.sh" "$TESTS_DIR/module-proof.sh" "$TESTS_DIR/agent-proof.sh" "$TESTS_DIR/lab-accounts.sh" "$TESTS_DIR/clickhouse-proof.sh" "$TESTS_DIR/mutation-test.sh"
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
    grep -qF 'readonly SERVICE_NAMES=(postgres platform web playbooks nats gateway relay clickhouse chschema)' "$CH_INIT_FILE"
expect "init.sh lists exactly the services of compose.yaml" init_lists_compose_services
expect "init.sh warns by name about a nats.conf without max_file_store and a gateway certificate with more names" init_warns_on_old_files
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
