#!/usr/bin/env bash
# Usage: deploy/compose/tests/compose-lab.sh <task-id>
# Live proof inside a booted ubuntu-single lab (LAB_PROFILE=ubuntu-single lab/up.sh <task-id>), never on the host: Docker and the compose plugin come
# from the Ubuntu archive through the lab proxy. Needs target/deploy-compose/image from deploy/compose/build.sh.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$(dirname "$TESTS_DIR")"
REPO_DIR="$(dirname "$(dirname "$COMPOSE_DIR")")"
readonly TESTS_DIR COMPOSE_DIR REPO_DIR
readonly IMAGE_DIR="$REPO_DIR/target/deploy-compose/image"
readonly READY_ATTEMPTS=90
readonly API_PORT=8443
readonly ADMIN_PASSWORD="a-long-admin-passphrase-for-the-lab"
readonly ANALYST_PASSWORD="a-long-analyst-passphrase-for-the-lab"
readonly STORE_ARGS="/var/lib/ostyr/accounts.json /var/lib/ostyr/audit-cli.log /run/secrets/store_key /etc/ostyr/compromised.txt"

task_id="${1:?usage: compose-lab.sh <task-id>}"
lab_state="$REPO_DIR/lab/state/$task_id"
read -r _ vm_user vm_address <"$lab_state/vms.txt"
failures=0

ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

remote() {
    ssh -n "${ssh_options[@]}" "$vm_user@$vm_address" "$@"
}

remote_stdin() {
    ssh "${ssh_options[@]}" "$vm_user@$vm_address" "$@"
}

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

compose() {
    remote "cd compose && sudo docker compose $*"
}

wait_ready() {
    remote "for attempt in \$(seq 1 $READY_ATTEMPTS); do sudo curl --silent --fail --cacert compose/secrets/ca.crt https://localhost:$API_PORT/health && exit 0; sleep 2; done; exit 1"
}

analyst_code() {
    printf 'totp %s\n' "$1" | remote_stdin "cd compose && sudo docker compose run --rm -T platform /usr/local/bin/auth_tool $STORE_ARGS"
}

login_token() {
    local body
    body="$(printf '{"username":"analyst","password":"%s","totp_code":"%s"}' "$ANALYST_PASSWORD" "$1")"
    remote "sudo curl --silent --fail --cacert compose/secrets/ca.crt -H 'Content-Type: application/json' -d '$body' https://localhost:$API_PORT/auth/login" \
        | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}

status_of() {
    remote "sudo curl --silent --output /dev/null --write-out '%{http_code}' --cacert compose/secrets/ca.crt -H 'Authorization: Bearer $1' https://localhost:$API_PORT$2"
}

all_routes_answer() {
    local route
    for route in /alerts /cases /assets /risk/entities; do
        [[ "$(status_of "$1" "$route")" == 200 ]] || return 1
    done
}

copy_into_vm() {
    tar -C "$1" "${@:3}" -cf - . | remote_stdin "tar -C $2 -xf -"
}

remote "if [ -d compose ]; then cd compose && sudo docker compose down -v; fi"
remote "sudo rm -rf compose image && mkdir -p compose image"
copy_into_vm "$COMPOSE_DIR" compose --exclude=secrets
copy_into_vm "$IMAGE_DIR" image
remote "command -v docker >/dev/null && docker compose version >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 openssl" >/dev/null
remote "cd image && sudo docker build -t ostyr-platform:local ."

expect "init.sh refuses a name starting with a dash before writing" absent remote "cd compose && sudo ./init.sh -x"
expect "init.sh refuses a name with a space before writing" absent remote "cd compose && sudo ./init.sh 'a b'"
expect "no secrets directory exists after a refusal" absent remote "test -e compose/secrets"
remote "cd compose && sudo ./init.sh lab.example"
remote "cd compose && sudo find secrets -type f -exec sha256sum {} + | sort >/tmp/secrets-before && sudo ./init.sh lab.example >/dev/null \
    && sudo find secrets -type f -exec sha256sum {} + | sort >/tmp/secrets-after"
expect "a second init.sh changes no file" remote "cmp /tmp/secrets-before /tmp/secrets-after"
remote "cd compose && sudo find secrets -exec stat -c '%a %u %n' {} +"

compose "up -d"
expect "the API answers /health over TLS" wait_ready
compose "ps"

analyst_secret="$(remote "cd compose && sudo bash tests/lab-accounts.sh '$ADMIN_PASSWORD' '$ANALYST_PASSWORD'")"
printf 'info analyst enrolled: %s\n' "$([[ -n "$analyst_secret" ]] && echo yes || echo no)"
token="$(login_token "$(analyst_code "$analyst_secret")")"
printf 'info analyst token obtained: %s\n' "$([[ -n "$token" ]] && echo yes || echo no)"
expect "the analyst reads /alerts, /cases, /assets and /risk/entities (200)" all_routes_answer "$token"

compose "restart"
expect "the API answers again after a restart" wait_ready
token="$(login_token "$(analyst_code "$analyst_secret")")"
expect "the account and the data survive a restart" all_routes_answer "$token"

platform_container="$(remote "cd compose && sudo docker compose ps -q platform")"
expect "the platform image runs as user 65532" test "$(remote "sudo docker inspect --format '{{.Config.User}}' $platform_container")" = 65532:65532
expect "the platform root filesystem is read-only" test "$(remote "sudo docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' $platform_container")" = true
expect "the platform drops every capability" test "$(remote "sudo docker inspect --format '{{.HostConfig.CapDrop}}' $platform_container")" = "[ALL]"
expect "the platform has no-new-privileges" test "$(remote "sudo docker inspect --format '{{.HostConfig.SecurityOpt}}' $platform_container")" = "[no-new-privileges:true]"
expect "no secret value is in the platform environment" absent remote "sudo docker inspect --format '{{.Config.Env}}' $platform_container | grep -i -e password -e BEGIN"
expect "only the API port listens on the host" test "$(remote "ss -ltn | awk 'NR>1 {print \$4}' | grep -c -e ':5432\$' || true")" = 0
expect "5432 is closed from the host network" absent remote "nc -z -w 3 $vm_address 5432 || nc -z -w 3 127.0.0.1 5432"
remote "ss -ltn"

if [[ "$failures" -ne 0 ]]; then
    printf '%s check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'all checks passed\n'
