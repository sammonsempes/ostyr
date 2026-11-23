#!/usr/bin/env bash
# Usage: deploy/compose/tests/mutation-test.sh static
#        deploy/compose/tests/mutation-test.sh parsed
# Runs every mutated copy of compose.yaml (make-mutants.py) through one check and expects it refused by the named check.
# static: static-test.sh on the host (no Docker). parsed: `docker compose config --format json` and config-check.py, run where Docker is
# (the lab VM, from inside the compose directory), the mutated copies being written next to compose.yaml. dollar_default is refused by the static check
# only (compose renders its default, so the parsed configuration is identical); the lab runs both modes.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$(dirname "$TESTS_DIR")"
readonly TESTS_DIR COMPOSE_DIR
readonly GRAMMAR="compose.yaml uses only the allowed YAML shapes"
readonly PORTS="only the API and web ports are published, in any syntax"
readonly VOLUMES="the web service mounts exactly its settings directory and its state volume"
readonly SECRETS="the web service is hardened, publishes 9443 and holds three secrets"
readonly PORT_OWNERS="the platform publishes 8443, web 9443 and postgres nothing"
readonly BINDS="every service mounts only its own volumes and binds"
readonly CAPS="only postgres adds capabilities"
readonly DEFINITIONS="the volume and secret definitions are exactly the expected ones"
readonly PARSED="the parsed configuration equals the committed projection"
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
    [profiled_service]="$GRAMMAR" [dollar_default]="$INTERPOLATION" [pg_ca_store_key]="$DEFINITIONS" [pg_publish_8443]="$PORT_OWNERS" [web_cap_add]="$CAPS" [pg_bind_secrets]="$BINDS" [web_bind_etc]="$VOLUMES"
)
declare -A STRAY_REFUSAL=([override_file]="$STRAY" [dotenv_compose_file]="$STRAY")
declare -A PARSED_REFUSAL=()
for mutant in "${!STATIC_REFUSAL[@]}"; do
    PARSED_REFUSAL[$mutant]="$PARSED"
done
unset 'PARSED_REFUSAL[dollar_default]'
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
