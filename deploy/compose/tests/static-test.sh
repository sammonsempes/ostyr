#!/usr/bin/env bash
# Usage: deploy/compose/tests/static-test.sh
# Static checks of the compose files on the host: docker compose config when Docker is installed, shellcheck when installed, and greps for
# the hardening the deployment promises. Builds and runs nothing.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$(dirname "$TESTS_DIR")"
readonly TESTS_DIR COMPOSE_DIR
readonly COMPOSE_FILE="${STATIC_TEST_COMPOSE_FILE:-$COMPOSE_DIR/compose.yaml}"
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

web_mounts_no_secrets_directory() {
    ! web_service | grep -v '^    secrets: ' | grep -q 'secrets'
}

published_port_items() {
    awk '/^ *ports:/ {match($0, /^ */); base = RLENGTH; inside = 1; next}
        inside {match($0, /^ */); if (RLENGTH < base || (RLENGTH == base && $0 !~ /^ *- /)) {inside = 0}}
        inside && /^ *- / {sub(/^ */, ""); print}' "$COMPOSE_FILE"
}

only_the_two_ports_are_published() {
    [[ "$(published_port_items)" == '- "0.0.0.0:8443:8443"'$'\n''- "0.0.0.0:9443:9443"' ]] && ! grep -q '^ *ports:.' "$COMPOSE_FILE"
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
    for name in pg_password pg_service_password pg_server.key pg_server.crt ca.crt api_tls.key api_tls.crt store.key; do
        : >"$scratch/secrets/$name"
    done
    cp -r "$COMPOSE_FILE" "$COMPOSE_DIR/config" "$scratch/"
    docker compose -f "$scratch/compose.yaml" config -q
    rm -rf "$scratch"
}

if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    mkdir -p "$COMPOSE_DIR/../../target"
    expect "docker compose config accepts compose.yaml" compose_config_accepts
else
    printf 'info docker compose is NOT installed on this host: the compose config check was SKIPPED\n'
fi
if command -v shellcheck >/dev/null; then
    expect "shellcheck accepts the scripts" shellcheck --severity=warning "$COMPOSE_DIR/init.sh" "$COMPOSE_DIR/build.sh" "$COMPOSE_DIR/config/pg-init-service-role.sh" "$TESTS_DIR/static-test.sh" "$TESTS_DIR/compose-lab.sh" "$TESTS_DIR/pg-proofs.sh" "$TESTS_DIR/stage-file-test.sh" "$TESTS_DIR/web-proof.sh"
else
    printf 'info shellcheck is not installed: skipped\n'
fi

expect "no PostgreSQL port is published" absent grep -e '5432' "$COMPOSE_FILE"
expect "only the API and web ports are published, in any syntax" only_the_two_ports_are_published
expect "the web service mounts no part of the secrets directory" web_mounts_no_secrets_directory
expect "the web service is hardened, publishes 9443 and holds three secrets" web_is_hardened
for refused_secret in pg_password pg_service_password pg_server store_key; do
    expect "the web service holds no $refused_secret secret" web_lacks "$refused_secret"
done
expect "the web service runs web_ui on its own settings file" web_has 'command: \["/usr/local/bin/web_ui", "/etc/ostyr/web-ui.yaml"\]'
expect "the platform trusts the web address only as forwarder" grep -qx '  trusted_forwarders: 172.29.63.10' "$COMPOSE_DIR/config/module.yaml"
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
