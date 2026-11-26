#!/usr/bin/env bash
# Usage: deploy/compose/tests/mutation-test.sh static
#        deploy/compose/tests/mutation-test.sh parsed
# Runs every mutated copy of compose.yaml (make-mutants.py) through one check and expects it refused by the named check.
# static: static-test.sh on the host (no Docker). parsed: `docker compose config --format json` and config-check.py, run where Docker is
# (the lab VM, from inside the compose directory), the mutated copies being written next to compose.yaml. dollar_default, esc_secopt, esc_pgcmd, esc_tmpfs, env_passthrough, bin_capadd, bin_pgsecret, bin_platform_cmd, flow_anchor and flow_alias are refused by the static check
# only (compose renders its default, so the parsed configuration is identical); the lab runs both modes.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$(dirname "$TESTS_DIR")"
readonly TESTS_DIR COMPOSE_DIR
readonly GRAMMAR="compose.yaml uses only the allowed YAML shapes"
readonly PORTS="only the API, web and relay ports are published, in any syntax"
readonly VOLUMES="the web service mounts exactly its settings directory and its state volume"
readonly SECRETS="the web service is hardened, publishes 9443 and holds three secrets"
readonly PORT_OWNERS="the platform publishes 8443, web 9443 and postgres nothing"
readonly BINDS="every service mounts only its own volumes and binds"
readonly CAPS="only postgres adds capabilities"
readonly PLAYBOOKS="the playbooks service is hardened, runs as 65533 and holds only its password copy and the CA"
readonly NATS_HARD="the nats service is hardened, pinned by digest, publishes no port and holds only its three secrets"
readonly GATEWAY_HARD="the gateway service is hardened, runs as 65534 and holds only its five secrets"
readonly RELAY_HARD="the relay service is hardened, runs as 65531 and holds no secret"
readonly CH_HARD="the clickhouse service is hardened, pinned by digest, publishes no port and holds only its three secrets"
readonly CHSCHEMA_HARD="the chschema service is hardened, runs as 65530 and holds only the CA and its password"
readonly SIEM_HARD="the siem service is hardened, runs as 65529 and holds only the CA and its two passwords"
readonly METRICS_HARD="the metrics service is hardened, runs as 65528 and holds only the CA and its two passwords"
readonly ALERTS_HARD="the metricalerts service is hardened, runs as 65527 and holds only the CA and its two password copies"
readonly INGEST_SECRETS="the ingest settings files name only their own secrets and state directory"
readonly INGEST_USERS="the ingest settings files name their own ClickHouse and NATS users"
readonly NATS_GOLDEN="the nats.conf written by the real init.sh equals the committed golden file"
readonly NATS_REFUSES="init.sh refuses an existing nats.conf that is not its own rendering, by name"
readonly NATS_SCOPED="the NATS consumer accounts are scoped to one durable each and have no create or purge subject"
readonly CH_ONE_IMAGE="both ClickHouse services use one pinned image"
readonly CH_USERS="ClickHouse has no default user, four hashed users on the compose subnet and a readonly=2 reader"
readonly CH_DEFINER="the ClickHouse materialised views run as schema, so the metrics writer needs no SELECT"
readonly CH_NO_PAGE="ClickHouse answers only POST / and GET /ping, no web page"
readonly PLANT_REFUSES="init.sh refuses a planted password file whose text is not the generated format, by name, and renders nothing"
readonly CH_REFUSES="init.sh refuses a users file that differs from the rendered one"
readonly GATEWAY_SAN="the gateway certificate names DNS:gateway only"
readonly INIT_SERVICES="init.sh lists exactly the services of compose.yaml"
readonly INIT_BEHAVES="init.sh warns by name about a gateway certificate with more names, and changes no file"
readonly PINNED="every image is pinned by digest or built locally"
readonly HARDENED="every service is read-only, drops capabilities and sets no-new-privileges"
readonly DEFINITIONS="the volume and secret definitions are exactly the expected ones"
readonly PARSED="the parsed configuration equals the committed projection"
readonly ALLOWLIST="compose.yaml holds only allowlisted characters outside the entrypoint"
readonly BACKSLASH="compose.yaml holds no backslash escape"
readonly PASSTHROUGH="compose.yaml has no environment entry without a value"
readonly ENTRYPOINT="the entrypoint script lines appear once, right after its -ec line"
readonly STRAY="no other compose file or .env is in the project directory"
readonly INTERPOLATION="compose.yaml interpolates no variable outside the entrypoint script"
readonly EXTRA_PORT=$'services:\n  postgres:\n    ports:\n      - "5000:5000"\n'
readonly MODE="${1:?usage: mutation-test.sh static|parsed}"
readonly MUTANT_PREFIX="mutant-"
failures=0

declare -A STATIC_REFUSAL=(
    [dash_newline]="$GRAMMAR" [ports_space]="$GRAMMAR" [ports_dquote]="$GRAMMAR" [ports_squote]="$GRAMMAR" [ports_explicit]="$GRAMMAR"
    [ports_flow]="$GRAMMAR" [port_unquoted]="$PORTS" [port_long]="$GRAMMAR" [pg_port]="no PostgreSQL port is published"
    [network_mode_host]="$GRAMMAR" [web_mount_dot]="$VOLUMES" [web_mount_dotdot]="$VOLUMES" [web_mount_parent]="$VOLUMES"
    [web_mount_secrets]="$VOLUMES" [web_secret_extra]="$SECRETS" [webstate_named]="$GRAMMAR" [webstate_named_block]="$DEFINITIONS"
    [profiled_service]="$GRAMMAR" [dollar_default]="$INTERPOLATION"
    [esc_secopt]="$BACKSLASH" [esc_pgcmd]="$BACKSLASH" [esc_tmpfs]="$BACKSLASH" [env_passthrough]="$PASSTHROUGH"
    [bin_capadd]="$ALLOWLIST" [bin_pgsecret]="$ALLOWLIST" [bin_platform_cmd]="$ALLOWLIST" [flow_anchor]="$ALLOWLIST" [flow_alias]="$ALLOWLIST"
    [env_passthrough_sameindent]="$GRAMMAR" [volumes_sameindent]="$GRAMMAR" [entrypoint_moved]="$ENTRYPOINT"
    [env_map_empty]="$PASSTHROUGH" [env_map_tilde]="$PASSTHROUGH" [env_map_null]="$PASSTHROUGH"
    [pg_ca_store_key]="$DEFINITIONS" [pg_publish_8443]="$PORT_OWNERS" [web_cap_add]="$CAPS" [pg_bind_secrets]="$BINDS" [web_bind_etc]="$VOLUMES"
    [playbooks_cap_add]="$CAPS" [playbooks_secret_extra]="$PLAYBOOKS" [playbooks_bind_secrets]="$BINDS" [playbooks_state_shared]="$BINDS"
    [playbooks_publish]="$PLAYBOOKS" [playbooks_root]="$PLAYBOOKS"
    [nats_cap_add]="$CAPS" [nats_publish]="$NATS_HARD" [nats_secret_extra]="$NATS_HARD" [nats_gateway_secret]="$NATS_HARD" [nats_bind_secrets]="$BINDS"
    [nats_state_shared]="$BINDS" [nats_unpinned]="$PINNED" [nats_writable]="$HARDENED"
    [gateway_cap_add]="$CAPS" [gateway_publish]="$GATEWAY_HARD" [gateway_secret_extra]="$GATEWAY_HARD" [gateway_nats_conf]="$GATEWAY_HARD"
    [gateway_bind_secrets]="$BINDS" [gateway_state_shared]="$BINDS" [gateway_log_debug]="$GATEWAY_HARD" [gateway_root]="$GATEWAY_HARD" [gateway_ip_moved]="$GATEWAY_HARD"
    [relay_cap_add]="$CAPS" [relay_secret_extra]="$RELAY_HARD" [relay_publish_extra]="$PORTS" [relay_bind_secrets]="$BINDS"
    [relay_state_shared]="$BINDS" [relay_root]="$RELAY_HARD" [relay_ip_moved]="$RELAY_HARD"
    [clickhouse_cap_add]="$CAPS" [clickhouse_publish]="$CH_HARD" [clickhouse_secret_extra]="$CH_HARD" [clickhouse_bind_secrets]="$BINDS"
    [clickhouse_state_shared]="$BINDS" [clickhouse_unpinned]="$PINNED" [clickhouse_root]="$CH_HARD" [clickhouse_writable]="$HARDENED"
    [siem_cap_add]="$CAPS" [siem_publish]="$SIEM_HARD" [siem_secret_metrics]="$SIEM_HARD" [siem_secret_admin]="$SIEM_HARD" [siem_bind_secrets]="$BINDS"
    [siem_state_shared]="$BINDS" [siem_root]="$SIEM_HARD"
    [metrics_cap_add]="$CAPS" [metrics_publish]="$METRICS_HARD" [metrics_secret_ingest]="$METRICS_HARD" [metrics_bind_secrets]="$BINDS"
    [metrics_state_shared]="$BINDS" [metrics_root]="$METRICS_HARD"
    [metricalerts_cap_add]="$CAPS" [metricalerts_publish]="$ALERTS_HARD" [metricalerts_secret_pg]="$ALERTS_HARD" [metricalerts_secret_nats]="$ALERTS_HARD"
    [metricalerts_bind_secrets]="$BINDS" [metricalerts_state_shared]="$BINDS" [metricalerts_root]="$ALERTS_HARD"
    [chschema_cap_add]="$CAPS" [chschema_secret_extra]="$CHSCHEMA_HARD" [chschema_bind_secrets]="$BINDS" [chschema_root]="$CHSCHEMA_HARD"
    [chschema_image_other]="$CH_ONE_IMAGE" [chschema_anonymous_volume]="the chschema service keeps its data and log directories on tmpfs"
)
declare -A STRAY_REFUSAL=([override_file]="$STRAY" [dotenv_compose_file]="$STRAY")
declare -A PARSED_REFUSAL=()
for mutant in "${!STATIC_REFUSAL[@]}"; do
    PARSED_REFUSAL[$mutant]="$PARSED"
done
unset 'PARSED_REFUSAL[dollar_default]' 'PARSED_REFUSAL[esc_secopt]' 'PARSED_REFUSAL[esc_pgcmd]' 'PARSED_REFUSAL[esc_tmpfs]' 'PARSED_REFUSAL[env_passthrough]' 'PARSED_REFUSAL[bin_capadd]' 'PARSED_REFUSAL[bin_pgsecret]' 'PARSED_REFUSAL[bin_platform_cmd]' 'PARSED_REFUSAL[flow_anchor]' 'PARSED_REFUSAL[flow_alias]'
for mutant in "${!STRAY_REFUSAL[@]}"; do
    PARSED_REFUSAL[$mutant]="$PARSED"
done

add_stray_input() {
    case "$1" in
        override_file) printf '%s' "$EXTRA_PORT" >"$2/compose.override.yaml" ;;
        dotenv_compose_file)
            printf '%s' "$EXTRA_PORT" >"$2/extra.yaml"
            printf 'COMPOSE_FILE=compose.yaml:extra.yaml\n' >"$2/.env"
            ;;
    esac
}

report() {
    local description="$1" output="$2" expected="$3"
    if grep -qxF "FAIL $expected" <<<"$output"; then
        printf 'ok   %s refused by: %s\n' "$description" "$expected"
    else
        printf 'FAIL %s was not refused by: %s\n%s\n' "$description" "$expected" "$output"
        failures=$((failures + 1))
    fi
}

static_run() {
    local name="$1" output
    output="$(STATIC_TEST_SKIP_PLANTED=1 STATIC_TEST_COMPOSE_FILE="$2/$name.yaml" "$TESTS_DIR/static-test.sh" 2>&1 || true)"
    report "static $name" "$output" "${STATIC_REFUSAL[$name]}"
}

stray_static_run() {
    local name="$1" project output
    project="$2/$name"
    mkdir -p "$project"
    cp "$COMPOSE_DIR/compose.yaml" "$project/compose.yaml"
    add_stray_input "$name" "$project"
    output="$(STATIC_TEST_SKIP_PLANTED=1 STATIC_TEST_PROJECT_DIR="$project" STATIC_TEST_COMPOSE_FILE="$project/compose.yaml" "$TESTS_DIR/static-test.sh" 2>&1 || true)"
    report "static $name" "$output" "${STRAY_REFUSAL[$name]}"
}

parsed_run() {
    local name="$1" output
    output="$(docker compose --profile "*" -f "$COMPOSE_DIR/$MUTANT_PREFIX$name.yaml" config --format json | python3 -I "$TESTS_DIR/config-check.py" "$COMPOSE_DIR" "$TESTS_DIR/expected-projection.json" || true)"
    report "parsed $name" "$output" "${PARSED_REFUSAL[$name]}"
}

stray_parsed_run() {
    local name="$1" project output
    project="$2/$name"
    mkdir -p "$project"
    cp -r "$COMPOSE_DIR/." "$project/"
    add_stray_input "$name" "$project"
    output="$(cd "$project" && docker compose --profile "*" config --format json | python3 -I "$TESTS_DIR/config-check.py" "$project" "$TESTS_DIR/expected-projection.json" || true)"
    report "parsed $name" "$output" "${PARSED_REFUSAL[$name]}"
}

file_static_run() {
    local name="$1" variable="$2" source="$3" expression="$4" expected="$5" extra_keys="${6:-}" output skip_planted=1
    if [[ "$expected" == "$PLANT_REFUSES" ]]; then
        skip_planted=0
    fi
    sed "$expression" "$source" >"$scratch/$name.file"
    if cmp -s "$source" "$scratch/$name.file"; then
        printf 'FAIL file %s: the mutation changed nothing\n' "$name"
        failures=$((failures + 1))
    else
        output="$(env "$variable=$scratch/$name.file" "STATIC_TEST_EXTRA_KEYS=$extra_keys" "STATIC_TEST_SKIP_PLANTED=$skip_planted" "$TESTS_DIR/static-test.sh" 2>&1 || true)"
        report "static $name" "$output" "$expected"
    fi
}

config_static_run() {
    local name="$1" file="$2" expression="$3" expected="$4" output
    rm -rf "${scratch:?}/config-$name"
    cp -r "$COMPOSE_DIR/config" "$scratch/config-$name"
    sed -i "$expression" "$scratch/config-$name/$file"
    if cmp -s "$COMPOSE_DIR/config/$file" "$scratch/config-$name/$file"; then
        printf 'FAIL config %s: the mutation changed nothing\n' "$name"
        failures=$((failures + 1))
    else
        output="$(STATIC_TEST_SKIP_PLANTED=1 STATIC_TEST_CONFIG_DIR="$scratch/config-$name" "$TESTS_DIR/static-test.sh" 2>&1 || true)"
        report "static $name" "$output" "$expected"
    fi
}

file_static_runs() {
    local init="$COMPOSE_DIR/init.sh" compose="$COMPOSE_DIR/compose.yaml" config="$COMPOSE_DIR/config/clickhouse-config.xml" schema="$COMPOSE_DIR/config/clickhouse-schema.sql"
    file_static_run metrics_select_granted STATIC_TEST_INIT_FILE "$init" 's|GRANT INSERT ON $CLICKHOUSE_DATABASE.metric_samples|GRANT INSERT, SELECT ON $CLICKHOUSE_DATABASE.metric_samples|' "$CH_USERS"
    file_static_run metrics_rollup_granted STATIC_TEST_INIT_FILE "$init" 's|GRANT INSERT ON $CLICKHOUSE_DATABASE.metric_samples</query>|&<query>GRANT INSERT ON $CLICKHOUSE_DATABASE.metric_rollup_1m</query>|' "$CH_USERS"
    file_static_run view_definer_removed STATIC_TEST_CH_SCHEMA_FILE "$schema" '0,/ DEFINER = schema SQL SECURITY DEFINER AS$/s// AS/' "$CH_DEFINER"
    file_static_run handlers_defaults_back STATIC_TEST_CH_CONFIG_FILE "$config" 's|<http_handlers>|<http_handlers><defaults/>|' "$CH_NO_PAGE"
    file_static_run handlers_play_added STATIC_TEST_CH_CONFIG_FILE "$config" 's|<url>/ping</url>|<url>/play</url>|' "$CH_NO_PAGE"
    file_static_run gateway_san_widened STATIC_TEST_INIT_FILE "$init" 's|DNS:gateway "$scratch"|DNS:gateway,DNS:platform "$scratch"|' "$GATEWAY_SAN"
    file_static_run service_name_dropped STATIC_TEST_INIT_FILE "$init" '/^readonly SERVICE_NAMES=/s| metricalerts)|)|' "$INIT_SERVICES"
    file_static_run compose_service_added STATIC_TEST_COMPOSE_FILE "$compose" 's|^  chschema:$|  state:\n    image: x\n&|' "$INIT_SERVICES"
    file_static_run compose_digit_service_added STATIC_TEST_COMPOSE_FILE "$compose" 's|^  chschema:$|  redis2:\n    image: x\n&|' "$INIT_SERVICES" redis2
    file_static_run gateway_condition_disabled STATIC_TEST_INIT_FILE "$init" 's|if \[\[ "$actual" != "$expected" \]\]; then|if false; then|' "$INIT_BEHAVES"
    file_static_run nats_create_export STATIC_TEST_INIT_FILE "$init" 's|accounts: \[$account\] }$|&\n        { service: "$JS.API.CONSUMER.CREATE.x", accounts: [$account] }|' "$NATS_SCOPED"
    file_static_run nats_dead_to_gateway STATIC_TEST_INIT_FILE "$init" 's|accounts: \[SIEM, METRICS\] }|accounts: [SIEM, METRICS, GATEWAY] }|' "$NATS_SCOPED"
    file_static_run nats_inbox_shared STATIC_TEST_INIT_FILE "$init" 's|"_INBOX_$user.>"|"_INBOX.>"|' "$NATS_SCOPED"
    file_static_run nats_durable_shared STATIC_TEST_INIT_FILE "$init" 's|METRICS:metrics_ingest:metrics-ingest)|METRICS:metrics_ingest:siem-ingest)|' "$NATS_SCOPED"
    file_static_run nats_stream_delete_export STATIC_TEST_INIT_FILE "$init" 's|^            { service: "$NATS_DEAD_SUBJECT", accounts: \[SIEM, METRICS\] }$|&\n            { service: "$JS.API.STREAM.DELETE.events", accounts: [SIEM] }|' "$NATS_GOLDEN"
    file_static_run nats_stream_delete_import STATIC_TEST_INIT_FILE "$init" 's|^            { service: { account: EVENTS, subject: "$NATS_DEAD_SUBJECT" } }$|&\n            { service: { account: EVENTS, subject: "$JS.API.STREAM.DELETE.events" } }|' "$NATS_GOLDEN"
    file_static_run nats_stream_delete_allow STATIC_TEST_INIT_FILE "$init" 's|^                        "$NATS_DEAD_SUBJECT"$|&\n                        "$JS.API.STREAM.DELETE.events"|' "$NATS_GOLDEN"
    file_static_run nats_extra_subscribe STATIC_TEST_INIT_FILE "$init" 's|subscribe: { allow: \["_INBOX_$user.>"\] }|subscribe: { allow: ["_INBOX_$user.>", "events.*"] }|' "$NATS_GOLDEN"
    file_static_run nats_variable_widening STATIC_TEST_INIT_FILE "$init" 's|^nats_consumer_account() {$|WIDEN=events.x\n&|; s|^                        "$NATS_DEAD_SUBJECT"$|&\n                        "\\$JS.API.STREAM.DELETE.$WIDEN"|' "$NATS_GOLDEN"
    file_static_run nats_second_accounts_block STATIC_TEST_INIT_FILE "$init" 's|^$(nats_accounts "$admin_password".*$|&\naccounts { EVIL { jetstream: enabled } }|' "$NATS_GOLDEN"
    file_static_run nats_include_added STATIC_TEST_INIT_FILE "$init" 's|^tls {$|include /run/secrets/evil.conf\n&|' "$NATS_GOLDEN"
    file_static_run nats_authorization_block STATIC_TEST_INIT_FILE "$init" 's|^$(nats_accounts "$admin_password".*$|authorization { token: x }\n&|' "$NATS_GOLDEN"
    file_static_run nats_accounts_redefined STATIC_TEST_INIT_FILE "$init" 's|^make_nats_conf() {$|nats_accounts() { printf "accounts { }\\n"; }\n\n&|' "$NATS_GOLDEN"
    file_static_run nats_jetstream_widened STATIC_TEST_INIT_FILE "$init" 's|^                        "$NATS_DEAD_SUBJECT"$|&\n                        "\\$JS.API.STREAM.DELETE.events"|' "$NATS_GOLDEN"
    file_static_run nats_refusal_removed STATIC_TEST_INIT_FILE "$init" '/^make_nats_conf() {$/,/^make_clickhouse_users() {$/s|if ! cmp -s "$SECRETS_DIR/$name" "$temporary"; then|if false; then|' "$NATS_REFUSES"
    config_static_run siem_admin_clickhouse siem-ingest.yaml 's|^clickhouse_user: ingest|clickhouse_user: schema|' "$INGEST_USERS"
    config_static_run metrics_nats_siem metrics-ingest.yaml 's|nats_user: metrics_ingest|nats_user: siem_ingest|' "$INGEST_USERS"
    config_static_run alerts_writer_clickhouse metric-alerts-fetch.yaml 's|^user: reader|user: ingest|' "$INGEST_USERS"
    config_static_run siem_foreign_secret siem-ingest.yaml 's|/run/secrets/nats_siem_password|/run/secrets/nats_metrics_password|' "$INGEST_SECRETS"
    config_static_run alerts_foreign_state metric-alerts.yaml 's|/var/lib/ostyr-metric-alerts/|/var/lib/ostyr-siem/|' "$INGEST_SECRETS"
    config_static_run alerts_pg_superuser_secret metric-alerts-pg.yaml 's|/run/secrets/metricalerts_pg_password|/run/secrets/pg_password|' "$INGEST_SECRETS"
    file_static_run base64_check_removed STATIC_TEST_INIT_FILE "$init" 's|if \[\[ ! "$content" =~ .*; then|if false; then|' "$PLANT_REFUSES"
    file_static_run users_check_removed STATIC_TEST_INIT_FILE "$init" 's|if ! cmp -s "$SECRETS_DIR/$name" "$temporary"; then|if false; then|' "$CH_REFUSES"
}

if [[ "$MODE" == static ]]; then
    mkdir -p "$COMPOSE_DIR/../../target"
    scratch="$(mktemp -d "$COMPOSE_DIR/../../target/mutants.XXXXXX")"
    python3 -I "$TESTS_DIR/make-mutants.py" "$COMPOSE_DIR/compose.yaml" "$scratch"
    file_static_runs
    for name in "${!STATIC_REFUSAL[@]}"; do
        static_run "$name" "$scratch"
    done
    for name in "${!STRAY_REFUSAL[@]}"; do
        stray_static_run "$name" "$scratch"
    done
    rm -rf "$scratch"
else
    python3 -I "$TESTS_DIR/make-mutants.py" "$COMPOSE_DIR/compose.yaml" "$COMPOSE_DIR" "$MUTANT_PREFIX"
    for name in "${!STATIC_REFUSAL[@]}"; do
        [[ -n "${PARSED_REFUSAL[$name]:-}" ]] && parsed_run "$name"
    done
    rm -f "$COMPOSE_DIR/$MUTANT_PREFIX"*.yaml
    mkdir -p "$COMPOSE_DIR/../../target"
    scratch="$(mktemp -d "$COMPOSE_DIR/../../target/mutants.XXXXXX")"
    for name in "${!STRAY_REFUSAL[@]}"; do
        stray_parsed_run "$name" "$scratch"
    done
    rm -rf "$scratch"
fi

if [[ "$failures" -ne 0 ]]; then
    printf '%s mutant(s) not refused\n' "$failures" >&2
    exit 1
fi
printf 'all mutants refused\n'
