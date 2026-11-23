#!/usr/bin/env bash
# Usage: deploy/compose/tests/mutation-test.sh static
#        deploy/compose/tests/mutation-test.sh parsed
# Runs every mutated copy of compose.yaml (make-mutants.py) through one check and expects it refused by the named check.
# static: static-test.sh on the host (no Docker). parsed: `docker compose config --format json` and config-check.py, run where Docker is
# (the lab VM, from inside the compose directory), the mutated copies being written next to compose.yaml.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$(dirname "$TESTS_DIR")"
readonly TESTS_DIR COMPOSE_DIR
readonly GRAMMAR="compose.yaml uses only the allowed YAML shapes"
readonly PORTS="only the API and web ports are published, in any syntax"
readonly VOLUMES="the web service mounts exactly its settings directory and its state volume"
readonly SECRETS="the web service is hardened, publishes 9443 and holds three secrets"
readonly PARSED_PORTS="published ports are exactly 0.0.0.0:8443->8443 and 0.0.0.0:9443->9443"
readonly PARSED_MODE="no service sets network_mode"
readonly PARSED_BINDS="web binds neither the compose directory, the secrets directory nor a parent or child of it"
readonly PARSED_SECRETS="web holds exactly the three secrets pg_ca, api_tls_key and api_tls_cert"
readonly MODE="${1:?usage: mutation-test.sh static|parsed}"
readonly MUTANT_PREFIX="mutant-"
failures=0

declare -A STATIC_REFUSAL=(
    [dash_newline]="$GRAMMAR" [ports_space]="$GRAMMAR" [ports_dquote]="$GRAMMAR" [ports_squote]="$GRAMMAR" [ports_explicit]="$GRAMMAR"
    [ports_flow]="$GRAMMAR" [port_unquoted]="$PORTS" [port_long]="$GRAMMAR" [pg_port]="no PostgreSQL port is published"
    [network_mode_host]="$GRAMMAR" [web_mount_dot]="$VOLUMES" [web_mount_dotdot]="$VOLUMES" [web_mount_parent]="$VOLUMES"
    [web_mount_secrets]="$VOLUMES" [web_secret_extra]="$SECRETS"
)
declare -A PARSED_REFUSAL=(
    [dash_newline]="$PARSED_PORTS" [ports_space]="$PARSED_PORTS" [ports_dquote]="$PARSED_PORTS" [ports_squote]="$PARSED_PORTS"
    [ports_explicit]="$PARSED_PORTS" [ports_flow]="$PARSED_PORTS" [port_unquoted]="$PARSED_PORTS" [port_long]="$PARSED_PORTS"
    [pg_port]="$PARSED_PORTS" [network_mode_host]="$PARSED_MODE" [web_mount_dot]="$PARSED_BINDS" [web_mount_dotdot]="$PARSED_BINDS"
    [web_mount_parent]="$PARSED_BINDS" [web_mount_secrets]="$PARSED_BINDS" [web_secret_extra]="$PARSED_SECRETS"
)

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

parsed_run() {
    local name="$1" output
    output="$(docker compose -f "$COMPOSE_DIR/$MUTANT_PREFIX$name.yaml" config --format json | python3 -I "$TESTS_DIR/config-check.py" "$COMPOSE_DIR" || true)"
    report "parsed $name" "$output" "${PARSED_REFUSAL[$name]}"
}

if [[ "$MODE" == static ]]; then
    scratch="$(mktemp -d "$COMPOSE_DIR/../../target/mutants.XXXXXX")"
    python3 -I "$TESTS_DIR/make-mutants.py" "$COMPOSE_DIR/compose.yaml" "$scratch"
    for name in "${!STATIC_REFUSAL[@]}"; do
        static_run "$name" "$scratch"
    done
    rm -rf "$scratch"
else
    python3 -I "$TESTS_DIR/make-mutants.py" "$COMPOSE_DIR/compose.yaml" "$COMPOSE_DIR" "$MUTANT_PREFIX"
    for name in "${!PARSED_REFUSAL[@]}"; do
        parsed_run "$name"
    done
    rm -f "$COMPOSE_DIR/$MUTANT_PREFIX"*.yaml
fi

if [[ "$failures" -ne 0 ]]; then
    printf '%s mutant(s) not refused\n' "$failures" >&2
    exit 1
fi
printf 'all mutants refused\n'
