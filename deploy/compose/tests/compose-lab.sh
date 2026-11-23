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
PG_IMAGE="$(sed -n 's/^    image: \(postgres:.*\)$/\1/p' "$COMPOSE_DIR/compose.yaml")"
readonly PG_IMAGE
readonly ADMIN_PASSWORD="a-long-admin-passphrase-for-the-lab"
readonly ANALYST_PASSWORD="a-long-analyst-passphrase-for-the-lab"
readonly VM_WORK_DIR=/srv/ostyr-lab
readonly TOTP_STEP_SECONDS=30
readonly TOTP_STEP_ATTEMPTS=40
readonly LOCK_PROOF_WAIT_SECONDS=3
readonly STORE_ARGS="/var/lib/ostyr/accounts.json /var/lib/ostyr/audit-cli.log /run/secrets/store_key /etc/ostyr/compromised.txt"

task_id="${1:?usage: compose-lab.sh <task-id>}"
lab_state="$REPO_DIR/lab/state/$task_id"
read -r _ vm_user vm_address <"$lab_state/vms.txt"
failures=0

ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

remote_bare() {
    ssh -n "${ssh_options[@]}" "$vm_user@$vm_address" "$@"
}

remote() {
    remote_bare "cd $VM_WORK_DIR && $*"
}

remote_stdin() {
    ssh "${ssh_options[@]}" "$vm_user@$vm_address" "cd $VM_WORK_DIR && $*"
}

totp_step() {
    remote_bare "echo \$(( \$(date +%s) / $TOTP_STEP_SECONDS ))"
}

wait_after_step() {
    local used_step="$1" _attempt
    for _attempt in $(seq 1 "$TOTP_STEP_ATTEMPTS"); do
        [[ "$(totp_step)" -gt "$used_step" ]] && return 0
        sleep 1
    done
    return 1
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
    tar -C "$1" "${@:3}" -cf - . | remote_stdin "sudo tar -C $2 -xf -"
}

remote_bare "sudo mkdir -p $VM_WORK_DIR && sudo chown root:root $VM_WORK_DIR && sudo chmod 0755 $VM_WORK_DIR"
remote "if [ -d compose ]; then cd compose && sudo docker compose down -v; fi"
remote "sudo rm -rf compose image && sudo mkdir -p compose image"
copy_into_vm "$COMPOSE_DIR" compose --exclude=secrets
remote "sudo chown -R root:root compose && sudo chmod -R go-w compose"
copy_into_vm "$IMAGE_DIR" image
remote "command -v docker >/dev/null && docker compose version >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 openssl" >/dev/null
remote "cd image && sudo docker build -t ostyr-platform:local ."

expect "init.sh refuses a name starting with a dash before writing" absent remote "cd compose && sudo ./init.sh -x"
expect "init.sh refuses a name with a space before writing" absent remote "cd compose && sudo ./init.sh 'a b'"
expect "init.sh refuses the name ." absent remote "cd compose && sudo ./init.sh ."
expect "init.sh refuses the name x.-" absent remote "cd compose && sudo ./init.sh x.-"
expect "init.sh refuses an accented name under a UTF-8 locale" absent remote "cd compose && sudo env LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 ./init.sh 'é.example'"
expect "init.sh refuses a fullwidth name under a UTF-8 locale" absent remote "cd compose && sudo env LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 ./init.sh 'ａ.example'"
expect "init.sh refuses the name ß.x under a UTF-8 locale" absent remote "cd compose && sudo env LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 ./init.sh 'ß.x'"
expect "init.sh refuses an address with an octet above 255" absent remote "cd compose && sudo ./init.sh 999.1.1.1"
expect "no secrets directory exists after a refusal" absent remote "test -e compose/secrets"
remote "cd compose && sudo ./init.sh lab.example"
remote "cd compose && sudo find secrets -type f -exec sha256sum {} + | sort >/tmp/secrets-before && sudo ./init.sh lab.example >/dev/null \
    && sudo find secrets -type f -exec sha256sum {} + | sort >/tmp/secrets-after"
expect "a second init.sh changes no file" remote "cmp /tmp/secrets-before /tmp/secrets-after"
remote "cd compose && sudo mv secrets/api_tls.crt /tmp/api_tls.crt.keep"
expect "init.sh refuses a partial TLS set naming the file" remote "cd compose && sudo ./init.sh lab.example 2>&1 | grep -q 'missing: api_tls.crt'"
remote "cd compose && sudo mv /tmp/api_tls.crt.keep secrets/api_tls.crt"
long_label="$(printf 'a%.0s' $(seq 1 63))"
long_name="$long_label.$long_label.$long_label.${long_label:0:61}"
remote "sudo rm -rf longname && sudo mkdir longname && sudo cp compose/init.sh longname/ && cd longname && sudo ./init.sh $long_name"
expect "a 253-character name verifies and sits in the SAN" remote "cd longname && sudo openssl verify -CAfile secrets/ca.crt secrets/api_tls.crt && sudo openssl x509 -in secrets/api_tls.crt -noout -ext subjectAltName | grep -q $long_name"
remote "sudo rm -rf killed && sudo mkdir killed && sudo cp compose/init.sh killed/ && cd killed && sudo timeout -s TERM 0.3 ./init.sh kill.example; true"
expect "a killed init.sh leaves no scratch directory" absent remote "sudo find killed/secrets -name '.tls.*' | grep -q ."
remote "cd killed && sudo rm -rf secrets && sudo ./init.sh kill.example && sudo openssl verify -CAfile secrets/ca.crt secrets/api_tls.crt"
for odd_name in 1.2.3 127.1 0x7f.1.1.1 1.2.3.4.5; do
    expect "init.sh refuses the all-numeric name $odd_name" absent remote "cd compose && sudo ./init.sh $odd_name"
done
remote "sudo rm -rf plant && sudo mkdir -m 0700 -p plant/secrets && sudo cp compose/init.sh plant/ && cd plant && sudo ln -s /tmp/leak-store secrets/store.key"
expect "init.sh refuses a dangling symlink at store.key" absent remote "cd plant && sudo ./init.sh plant.example"
expect "no key was written through the symlink" absent remote "test -e /tmp/leak-store"
remote "cd plant && sudo rm -rf secrets && sudo mkdir -m 0700 secrets && sudo ln -s /nowhere secrets/api_tls.crt"
expect "init.sh refuses a dangling symlink at a TLS name" absent remote "cd plant && sudo ./init.sh plant.example"
expect "no TLS file was published next to the planted link" absent remote "cd plant && sudo test -e secrets/ca.crt"
remote "cd plant && sudo rm -rf secrets && sudo ./init.sh plant.example && sudo truncate -s 5 secrets/store.key"
expect "init.sh refuses a short secret naming the file" remote "cd plant && ! sudo ./init.sh plant.example 2>&1 | grep -q 'secrets ready' && sudo ./init.sh plant.example 2>&1 | grep -q 'store.key is not 32 bytes'"
remote "cd plant && sudo rm -rf secrets && sudo mkdir -m 0700 secrets && sudo ln -s /root secrets2 && sudo mv secrets secrets.real && sudo ln -s secrets.real secrets"
expect "init.sh refuses a secrets directory that is a symlink" absent remote "cd plant && sudo ./init.sh plant.example"
remote "cd plant && sudo rm -rf secrets secrets.real secrets2 && sudo mkdir -m 0700 secrets && sudo chown 1000 secrets"
expect "init.sh refuses a secrets directory owned by uid 1000" absent remote "cd plant && sudo ./init.sh plant.example"
expect "a second concurrent init.sh is refused by the lock and the first finishes a full set" remote "sudo env INIT_LOCK_WAIT_SECONDS=$LOCK_PROOF_WAIT_SECONDS compose/tests/lock-proof.sh compose/init.sh"
remote "sudo rm -rf plant && sudo mkdir -m 0700 -p plant/secrets && sudo cp compose/init.sh plant/ && cd plant && sudo ./init.sh plant.example && sudo chmod 0644 secrets/store.key"
expect "init.sh refuses a secret with mode 0644 naming the file" remote "cd plant && sudo ./init.sh plant.example 2>&1 | grep -q 'store.key must have mode 600'"
remote "sudo rm -rf plant && sudo mkdir -m 0700 -p plant/secrets && sudo cp compose/init.sh plant/ && sudo chmod 0777 plant"
expect "init.sh refuses a world-writable parent of secrets" absent remote "cd plant && sudo ./init.sh plant.example"
remote "sudo rm -rf plant && sudo mkdir -p plant/inner/compose && sudo cp compose/init.sh plant/inner/compose/ && sudo chown 1000 plant/inner"
expect "init.sh refuses an ancestor owned by uid 1000" absent remote "cd plant/inner/compose && sudo ./init.sh plant.example"
remote "sudo chown root plant/inner && sudo chmod 0775 plant/inner"
expect "init.sh refuses a group-writable ancestor" absent remote "cd plant/inner/compose && sudo ./init.sh plant.example"
remote "sudo rm -rf /tmp/*ostyr-nl && sudo mkdir -p \"/tmp/\$(printf '\\nostyr-nl')/compose\" && sudo chown 1000 \"/tmp/\$(printf '\\nostyr-nl')\" && sudo cp compose/init.sh \"/tmp/\$(printf '\\nostyr-nl')/compose/\""
expect "init.sh refuses a user-owned ancestor with a newline in its name" absent remote "cd \"/tmp/\$(printf '\\nostyr-nl')/compose\" && sudo ./init.sh plant.example"
expect "no secrets directory was created under the newline path" absent remote "sudo test -e \"/tmp/\$(printf '\\nostyr-nl')/compose/secrets\""
remote "sudo rm -rf plant && sudo mkdir -m 0700 -p plant/secrets && sudo cp compose/init.sh plant/ && sudo mkfifo plant/secrets/.lock"
expect "init.sh refuses a FIFO as the lock file without hanging" absent remote "cd plant && sudo timeout 20 ./init.sh plant.example"
remote "sudo rm -rf plant && sudo mkdir -m 0700 -p plant/secrets && sudo cp compose/init.sh plant/ && sudo ln -s /tmp/lock-leak plant/secrets/.lock"
expect "init.sh refuses a symlink as the lock file" absent remote "cd plant && sudo ./init.sh plant.example"
expect "nothing was created through the lock symlink" absent remote "test -e /tmp/lock-leak"
remote "sudo rm -rf plant && sudo mkdir -p plant/secrets && sudo cp compose/init.sh plant/ && sudo chmod 0777 plant/secrets"
expect "init.sh refuses a secrets directory open to others" absent remote "cd plant && sudo ./init.sh plant.example"
expect "the installed certificates verify against the CA" remote "cd compose && sudo openssl verify -CAfile secrets/ca.crt secrets/pg_server.crt secrets/api_tls.crt"
remote "cd compose && sudo find secrets -exec stat -c '%a %u %n' {} +"

compose "up -d"
expect "the API answers /health over TLS" wait_ready
compose "ps"

analyst_secret="$(remote "cd compose && sudo bash tests/lab-accounts.sh '$ADMIN_PASSWORD' '$ANALYST_PASSWORD'")"
printf 'info analyst enrolled: %s\n' "$([[ -n "$analyst_secret" ]] && echo yes || echo no)"
token="$(login_token "$(analyst_code "$analyst_secret")")"
printf 'info analyst token obtained: %s\n' "$([[ -n "$token" ]] && echo yes || echo no)"
expect "the analyst reads /alerts, /cases, /assets and /risk/entities (200)" all_routes_answer "$token"

login_step="$(totp_step)"
compose "restart"
expect "the API answers again after a restart" wait_ready
expect "the next TOTP step began" wait_after_step "$login_step"
token="$(login_token "$(analyst_code "$analyst_secret")")"
expect "the account and the data survive a restart" all_routes_answer "$token"

proof_value() {
    printf '%s\n' "$pg_proofs" | sed -n "s/^$1 //p"
}

pg_proofs="$(remote_stdin "cd compose && sudo docker compose exec -T postgres bash -s" <"$TESTS_DIR/pg-proofs.sh")"
printf '%s\n' "$pg_proofs"
expect "the service role is not a superuser" test "$(proof_value superuser)" = f
expect "the service role cannot create roles" test "$(proof_value createrole)" = f
expect "the service role connects over verified TLS" test "$(proof_value tls)" = t
expect "the service role owns the database" test "$(proof_value owner)" = ostyr_service
expect "COPY TO PROGRAM is refused for the service role" test "$(proof_value program)" = 1
expect "COPY TO PROGRAM ran nothing" test "$(proof_value pwned)" = absent
expect "pg_read_file of the TLS key is refused" test "$(proof_value readfile)" = 1
expect "a plain-text connection is refused by pg_hba" test "$(proof_value plain)" = 1
expect "the service role cannot reach another database" test "$(proof_value otherdb)" = 1
expect "the superuser cannot log in over the network" test "$(proof_value superlogin)" = 1

platform_container="$(remote "cd compose && sudo docker compose ps -q platform")"
expect "the platform image runs as user 65532" test "$(remote "sudo docker inspect --format '{{.Config.User}}' $platform_container")" = 65532:65532
expect "the platform root filesystem is read-only" test "$(remote "sudo docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' $platform_container")" = true
expect "the platform drops every capability" test "$(remote "sudo docker inspect --format '{{.HostConfig.CapDrop}}' $platform_container")" = "[ALL]"
expect "the platform has no-new-privileges" test "$(remote "sudo docker inspect --format '{{.HostConfig.SecurityOpt}}' $platform_container")" = "[no-new-privileges:true]"
expect "no secret value is in the platform environment" absent remote "sudo docker inspect --format '{{.Config.Env}}' $platform_container | grep -i -e password -e BEGIN"
expect "only the API and web ports are published on the host" test "$(remote "sudo ss -ltnp | grep docker-proxy | awk '{print \$4}' | sed 's/.*://' | sort -un | xargs")" = "8443 9443"
parsed_config="$(remote "cd compose && sudo docker compose config --format json | python3 -I tests/config-check.py . " || true)"
printf '%s\n' "$parsed_config"
expect "the parsed configuration passes every port, mount and secret check" absent grep -q '^FAIL' <<<"$parsed_config"
expect "the parsed configuration was checked (five checks ran)" test "$(grep -c '^ok' <<<"$parsed_config")" -eq 5
mutation_output="$(remote "cd compose && sudo tests/mutation-test.sh parsed" || true)"
printf '%s\n' "$mutation_output"
expect "every mutated copy is refused by the parsed checks, dash_newline and web_mount_dot included" grep -q '^all mutants refused$' <<<"$mutation_output"
expect "5432 is closed from the host network" absent remote "nc -z -w 3 $vm_address 5432 || nc -z -w 3 127.0.0.1 5432"
remote "ss -ltn"

web_login_step="$(totp_step)"
expect "the next TOTP step began for the web login" wait_after_step "$web_login_step"
web_code="$(analyst_code "$analyst_secret")"
web_proofs="$(remote_stdin "cd compose && sudo bash -s -- '$ANALYST_PASSWORD' '$web_code' secrets/ca.crt" <"$TESTS_DIR/web-proof.sh")"
printf '%s\n' "$web_proofs"
expect "the web sign-in page is served over TLS" test "$(printf '%s\n' "$web_proofs" | sed -n 's/^login_page //p')" = 1
expect "the sign-in through the web service redirects (303)" test "$(printf '%s\n' "$web_proofs" | sed -n 's/^login_status //p')" = 303
expect "the alert list renders through the web service (200)" test "$(printf '%s\n' "$web_proofs" | sed -n 's/^alerts_status //p')" = 200
expect "plain HTTP on the web port is not served" test "$(printf '%s\n' "$web_proofs" | sed -n 's/^plain_http_status //p')" != 200
forged_body="$(remote "sudo curl --silent --cacert compose/secrets/ca.crt -H 'Forwarded: for=1.2.3.4' https://localhost:$API_PORT/health")"
printf 'info health with a forged Forwarded header from the host: %s\n' "$forged_body"
web_container="$(remote "cd compose && sudo docker compose ps -q web")"
expect "the web image runs as user 65532" test "$(remote "sudo docker inspect --format '{{.Config.User}}' $web_container")" = 65532:65532
expect "the web root filesystem is read-only" test "$(remote "sudo docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' $web_container")" = true
expect "the web service drops every capability" test "$(remote "sudo docker inspect --format '{{.HostConfig.CapDrop}}' $web_container")" = "[ALL]"
expect "the web service has no-new-privileges" test "$(remote "sudo docker inspect --format '{{.HostConfig.SecurityOpt}}' $web_container")" = "[no-new-privileges:true]"
expect "no secret value is in the web environment" absent remote "sudo docker inspect --format '{{.Config.Env}}' $web_container | grep -i -e password -e BEGIN"
expect "the web service mounts exactly the three secret files" test "$(remote "sudo docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' $web_container | tr ' ' '\n' | grep '/secrets' | xargs -r -n1 basename | sort | xargs")" = "api_tls.crt api_tls.key ca.crt"
expect "the web service mounts no database or store secret" absent remote "sudo docker inspect --format '{{range .Mounts}}{{.Destination}} {{end}}' $web_container | grep -e pg_password -e pg_service -e pg_server -e store_key"
expect "the web service sits at the address the platform trusts" test "$(remote "sudo docker inspect --format '{{(index .NetworkSettings.Networks \"ostyr_default\").IPAddress}}' $web_container")" = 172.29.63.10
expect "a client on the compose network without the service password cannot open the database" absent remote "sudo docker run --rm --network ostyr_default -e PGPASSWORD=wrong -e PGSSLMODE=require $PG_IMAGE psql -h postgres -U ostyr_service -d ostyr -c 'select 1'"

if [[ "$failures" -ne 0 ]]; then
    printf '%s check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'all checks passed\n'
