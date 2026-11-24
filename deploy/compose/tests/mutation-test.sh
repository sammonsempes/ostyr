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
    output="$(STATIC_TEST_COMPOSE_FILE="$2/$name.yaml" "$TESTS_DIR/static-test.sh" 2>&1 || true)"
    report "static $name" "$output" "${STATIC_REFUSAL[$name]}"
}

stray_static_run() {
    local name="$1" project output
    project="$2/$name"
    mkdir -p "$project"
    cp "$COMPOSE_DIR/compose.yaml" "$project/compose.yaml"
    add_stray_input "$name" "$project"
    output="$(STATIC_TEST_PROJECT_DIR="$project" STATIC_TEST_COMPOSE_FILE="$project/compose.yaml" "$TESTS_DIR/static-test.sh" 2>&1 || true)"
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

if [[ "$MODE" == static ]]; then
    mkdir -p "$COMPOSE_DIR/../../target"
    scratch="$(mktemp -d "$COMPOSE_DIR/../../target/mutants.XXXXXX")"
    python3 -I "$TESTS_DIR/make-mutants.py" "$COMPOSE_DIR/compose.yaml" "$scratch"
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
