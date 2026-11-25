#!/usr/bin/env bash
# Usage: deploy/compose/tests/compose-lab.sh <task-id>
# Build the agent first: cargo build --release --target x86_64-unknown-linux-musl -p agent-channel --example channel_agent
# Live proof inside a booted ubuntu-docker lab (LAB_PROFILE=ubuntu-docker lab/up.sh <task-id>), never on the host: the image holds Docker, the compose
# plugin and openssl (the daemon is restarted to read the proxy drop-in cloud-init writes after it started); on another profile they are installed from the Ubuntu archive through the lab proxy. Needs target/deploy-compose/image from deploy/compose/build.sh.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$(dirname "$TESTS_DIR")"
REPO_DIR="$(dirname "$(dirname "$COMPOSE_DIR")")"
readonly TESTS_DIR COMPOSE_DIR REPO_DIR
readonly IMAGE_DIR="$REPO_DIR/target/deploy-compose/image"
readonly READY_ATTEMPTS=90
readonly API_PORT=8443
readonly RELAY_PORT=7443
readonly NATS_PORT=4222
readonly NATS_BOX_IMAGE="natsio/nats-box:0.19.7@sha256:ffce8bd103383f179f8c7f11cf645726acf5d17280706c530c3b342dbe16334c"
readonly AGENT_BINARY="$REPO_DIR/target/x86_64-unknown-linux-musl/release/examples/channel_agent"
readonly VM_AGENT_BINARY=/srv/ostyr-lab/channel_agent
readonly VM_AGENT_DIR=/srv/ostyr-lab/agent-proof
readonly LOG_ATTEMPTS=30
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
    printf 'totp %s\n' "$1" | remote_stdin "cd compose && sudo docker compose run --rm -T platform /usr/local/bin/ostyr-auth $STORE_ARGS"
}

login_token() {
    local body
    body="$(printf '{"username":"%s","password":"%s","totp_code":"%s"}' "${2:-analyst}" "$ANALYST_PASSWORD" "$1")"
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
remote "command -v docker >/dev/null && command -v openssl >/dev/null && docker compose version >/dev/null 2>&1 || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io docker-compose-v2 openssl" >/dev/null
remote "sudo systemctl daemon-reload && sudo systemctl restart docker" >/dev/null
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
remote "sudo rm -rf plant && sudo mkdir -m 0700 -p plant/secrets && sudo cp compose/init.sh plant/ && cd plant && sudo ./init.sh plant.example && sudo chmod 0600 secrets/playbooks_pg_password && sudo sh -c 'head -c 33 /dev/zero | base64 -w 0 | head -c 44 >secrets/playbooks_pg_password' && sudo chmod 0400 secrets/playbooks_pg_password"
expect "init.sh refuses a password copy with other bytes naming it" remote "cd plant && ! sudo ./init.sh plant.example 2>&1 | grep -q 'secrets ready' && sudo ./init.sh plant.example 2>&1 | grep -q 'playbooks_pg_password differs from pg_service_password'"
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
remote "sudo rm -rf plant && sudo mkdir -m 0700 -p plant/secrets && sudo cp compose/init.sh plant/ && cd plant && sudo ./init.sh plant.example && sudo cp secrets/clickhouse_users /tmp/users-good"
remote "cd plant && sudo sed 's|^    </users>\$|        <evil><networks><ip>::/0</ip></networks><grants><query>GRANT SELECT ON ostyr.*</query></grants></evil>\n&|' /tmp/users-good | sudo tee secrets/clickhouse_users >/dev/null"
expect "init.sh refuses a users file with a one-line extra user, by name" remote "cd plant && sudo grep -q evil secrets/clickhouse_users && ! sudo ./init.sh plant.example 2>&1 | grep -q 'secrets ready' && sudo ./init.sh plant.example 2>&1 | grep -q 'clickhouse_users is not the file init.sh renders'"
remote "cd plant && sudo sed 's|GRANT INSERT ON ostyr.metric_samples|GRANT INSERT, SELECT ON ostyr.metric_samples|' /tmp/users-good | sudo tee secrets/clickhouse_users >/dev/null"
expect "init.sh refuses the cycle 1 metrics SELECT grant, by name" remote "cd plant && sudo grep -q 'INSERT, SELECT ON ostyr.metric_samples' secrets/clickhouse_users && sudo ./init.sh plant.example 2>&1 | grep -q 'clickhouse_users is not the file init.sh renders'"
remote "cd plant && sudo cp /tmp/users-good secrets/clickhouse_users"
expect "init.sh accepts the file it rendered" remote "cd plant && sudo ./init.sh plant.example 2>&1 | grep -q 'secrets ready'"
expect "the installed certificates verify against the CA" remote "cd compose && sudo openssl verify -CAfile secrets/ca.crt secrets/pg_server.crt secrets/api_tls.crt"
remote "cd compose && sudo find secrets -exec stat -c '%a %u %n' {} +"

compose "up -d"
expect "the API answers /health over TLS" wait_ready
compose "ps"

lab_accounts="$(remote "cd compose && sudo bash tests/lab-accounts.sh '$ADMIN_PASSWORD' '$ANALYST_PASSWORD'")"
analyst_secret="$(sed -n 's/^analyst //p' <<<"$lab_accounts")"
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
expect "only the API, web and relay ports are published on the host" test "$(remote "sudo ss -ltnp | grep docker-proxy | awk '{print \$4}' | sed 's/.*://' | sort -un | xargs")" = "7443 8443 9443"
project_listing="$(remote "find compose -mindepth 1 -maxdepth 1 ! -name secrets -printf '%f\\n' | sort | xargs")"
host_listing="$(find "$COMPOSE_DIR" -mindepth 1 -maxdepth 1 ! -name secrets -printf '%f\n' | sort | xargs)"
expect "the lab project directory holds only the committed files plus the generated secrets" test "$project_listing" = "$host_listing"
expect "no other compose file or .env is in the lab project directory" test -z "$(remote "find compose -maxdepth 1 \\( -name 'compose*.y*ml' -o -name 'docker-compose*' -o -name '.env*' \\) ! -name compose.yaml")"
parsed_config="$(remote "cd compose && sudo docker compose --profile '*' config --format json | python3 -I tests/config-check.py . tests/expected-projection.json" || true)"
printf '%s\n' "$parsed_config"
expect "the parsed configuration equals the committed projection" absent grep -q '^FAIL' <<<"$parsed_config"
expect "the parsed configuration was checked (one ok line)" test "$(grep -c '^ok' <<<"$parsed_config")" -eq 1
static_mutation_output="$(remote "cd compose && sudo tests/mutation-test.sh static" || true)"
printf '%s\n' "$static_mutation_output"
expect "every static mutant, dollar_default included, is refused by its named check in the lab" grep -q '^all mutants refused$' <<<"$static_mutation_output"
mutation_output="$(remote "cd compose && sudo tests/mutation-test.sh parsed" || true)"
printf '%s\n' "$mutation_output"
expect "every mutated copy is refused by the projection diff, dash_newline and web_mount_dot included" grep -q '^all mutants refused$' <<<"$mutation_output"
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

role_token() {
    local role="$1" secret
    secret="$(sed -n "s/^$role //p" <<<"$lab_accounts")"
    login_token "$(analyst_code "$secret")" "$role"
}

query_migrations() {
    local script
    script="PGPASSWORD=\"\$(cat /run/pgtls/service_password)\" psql \"host=postgres dbname=ostyr user=ostyr_service sslmode=verify-full sslrootcert=/run/secrets/pg_ca\" -At -c \"$1\""
    remote_stdin "cd compose && sudo docker compose exec -T postgres bash -s" <<<"$script"
}

readonly MODULE_COUNT=15
module_tokens=""
for role in analyst auditor responder reader; do
    expect "the next TOTP step began for the $role login" wait_after_step "$(totp_step)"
    module_tokens="$module_tokens $(role_token "$role")"
done
module_lines="$(remote_stdin "cd compose && sudo bash -s -- secrets/ca.crt $module_tokens" <"$TESTS_DIR/module-proof.sh")"
printf '%s\n' "$module_lines"
expect "the proof printed one line per mounted module" test "$(grep -c -E '^[a-z_]+ [01] [0-9]{3} [0-9]{3} [0-9]{3}$' <<<"$module_lines")" -eq "$MODULE_COUNT"
module_field() {
    awk -v module="$1" -v field="$2" '$1 == module { print $field }' <<<"$module_lines"
}
for module in alerts cases cmdb risk hunts certificates oncall dhcp compliance vulnerabilities remote_shell posture status grc attack_paths; do
    expect "$module: its path is in the OpenAPI document" test "$(module_field "$module" 2)" = 1
    expect "$module: no token is 401" test "$(module_field "$module" 3)" = 401
    expected_ok=200
    [[ "$module" == status ]] && expected_ok=201
    expect "$module: the owning role is answered $expected_ok" test "$(module_field "$module" 4)" = "$expected_ok"
    if [[ "$module" != hunts ]]; then
        expect "$module: the reader role (events.read only) is 403" test "$(module_field "$module" 5)" = 403
    fi
done
expect "the analyst has no audit.read: the remote shell list is 403" test "$(sed -n 's/^analyst_on_audit_route //p' <<<"$module_lines")" = 403
expect "the analyst has no status.write: opening an incident is 403" test "$(sed -n 's/^analyst_on_status_write //p' <<<"$module_lines")" = 403
migrations="$(query_migrations 'select namespace || chr(32) || count(*) from public.schema_migrations group by namespace order by namespace')"
printf 'migrations applied:\n%s\n' "$migrations"
readonly MIGRATION_NAMESPACES=14
expect "the 14 modules with a store (risk reads alerts) applied their migrations, each in its own namespace" test "$(grep -c -E '^[a-z_]+ [0-9]+$' <<<"$migrations")" -eq "$MIGRATION_NAMESPACES"
migrations_before="$(query_migrations 'select count(*) from public.schema_migrations')"
compose "restart"
expect "the API answers after a restart on the same pgdata" wait_ready
migrations_after="$(query_migrations 'select count(*) from public.schema_migrations')"
expect "a restart on an existing pgdata applies no migration again" test "$migrations_before" = "$migrations_after"

playbooks_container="$(remote "cd compose && sudo docker compose ps -q playbooks")"
inspect_playbooks() {
    remote "sudo docker inspect --format '$1' $playbooks_container"
}
expect "the playbooks service is running and has not restarted" test "$(inspect_playbooks '{{.State.Running}} {{.RestartCount}}')" = "true 0"
expect "the playbooks service runs as user 65533" test "$(inspect_playbooks '{{.Config.User}}')" = 65533:65533
expect "the playbooks root filesystem is read-only" test "$(inspect_playbooks '{{.HostConfig.ReadonlyRootfs}}')" = true
expect "the playbooks service drops every capability" test "$(inspect_playbooks '{{.HostConfig.CapDrop}}')" = "[ALL]"
expect "the playbooks service has no-new-privileges" test "$(inspect_playbooks '{{.HostConfig.SecurityOpt}}')" = "[no-new-privileges:true]"
expect "no secret value is in the playbooks environment" absent remote "sudo docker inspect --format '{{.Config.Env}}' $playbooks_container | grep -i -e password -e BEGIN"
expect "the playbooks service mounts exactly its password copy and the CA" test "$(remote "sudo docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' $playbooks_container | tr ' ' '\n' | grep '/secrets' | xargs -r -n1 basename | sort | xargs")" = "ca.crt playbooks_pg_password"
expect "the playbooks service publishes no port" test -z "$(inspect_playbooks '{{range $port, $bindings := .NetworkSettings.Ports}}{{if $bindings}}{{$port}} {{end}}{{end}}')"
expect "the password copy is mode 400 and owned by 65533" test "$(remote "cd compose && sudo stat -c '%a %u:%g' secrets/playbooks_pg_password")" = "400 65533:65533"
expect "the password copy holds the service password" remote "cd compose && sudo cmp secrets/playbooks_pg_password secrets/pg_service_password"
alert_sql="INSERT INTO alerts (tenant, id, rule_id, rule_title, severity, event_time, created, host_name, event_ids, summary, summary_truncated, summary_original_bytes) VALUES ('default', encode(sha256('t843'::bytea), 'hex'), 'lab-rule', 'Lab alert', 'high', '2026-11-24T00:00:00Z', 1, 'ws-0042', '[]'::jsonb, '{\\\"process\\\":{\\\"name\\\":\\\"whoami\\\"}}', false, 29)"
printf 'info alert stored: %s\n' "$(query_migrations "$alert_sql")"
expect "the playbooks service logs a round that read and simulated the alert" remote "cd compose && for attempt in \$(seq 1 $READY_ATTEMPTS); do sudo docker compose logs playbooks 2>&1 | grep -q 'playbooks round: 1 read, 1 simulated, 1 matches' && exit 0; sleep 2; done; exit 1"
remote "cd compose && sudo docker compose logs playbooks 2>&1 | tail -n 20"
expect "the round deleted the alert from the feed" test "$(query_migrations "select count(*) from playbook_outbox")" = 0
expect "the playbooks service is still running after the round" test "$(inspect_playbooks '{{.State.Running}} {{.RestartCount}}')" = "true 0"

nats_box() {
    local user="$1" password_file="$2"
    shift 2
    remote "pw=\$(sudo cat compose/secrets/$password_file) && sudo docker run --rm ${NATS_BOX_TTY:-} --network ostyr_default -v $VM_WORK_DIR/compose/secrets/ca.crt:/ca.crt:ro \
        $NATS_BOX_IMAGE nats --server tls://nats:$NATS_PORT --tlsfirst --tlsca /ca.crt --user $user --password \"\$pw\" $*"
}

service_container() {
    remote "cd compose && sudo docker compose ps -q $1"
}

inspect_service() {
    remote "sudo docker inspect --format '$2' $(service_container "$1")"
}

service_secret_files() {
    remote "sudo docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' $(service_container "$1") | tr ' ' '\n' | grep '/secrets' | xargs -r -n1 basename | sort | xargs"
}

published_ports() {
    inspect_service "$1" '{{range $port, $bindings := .NetworkSettings.Ports}}{{if $bindings}}{{$port}} {{end}}{{end}}'
}

for service in nats gateway relay; do
    expect "the $service service is running and has not restarted" test "$(inspect_service "$service" '{{.State.Running}} {{.RestartCount}}')" = "true 0"
    expect "the $service root filesystem is read-only" test "$(inspect_service "$service" '{{.HostConfig.ReadonlyRootfs}}')" = true
    expect "the $service service drops every capability" test "$(inspect_service "$service" '{{.HostConfig.CapDrop}}')" = "[ALL]"
    expect "the $service service has no-new-privileges" test "$(inspect_service "$service" '{{.HostConfig.SecurityOpt}}')" = "[no-new-privileges:true]"
    expect "no secret value is in the $service environment" absent remote "sudo docker inspect --format '{{.Config.Env}}' $(service_container "$service") | grep -i -e password -e BEGIN"
done
expect "the gateway runs as user 65534" test "$(inspect_service gateway '{{.Config.User}}')" = 65534:65534
expect "the relay runs as user 65531" test "$(inspect_service relay '{{.Config.User}}')" = 65531:65531
expect "the nats service has no capability in its process (CapEff 0)" test "$(remote "sudo docker exec $(service_container nats) /nats-server --version >/dev/null 2>&1; sudo grep CapEff /proc/\$(sudo docker inspect --format '{{.State.Pid}}' $(service_container nats))/status | awk '{print \$2}'")" = 0000000000000000
expect "nats publishes no port" test -z "$(published_ports nats)"
expect "the gateway publishes no port" test -z "$(published_ports gateway)"
expect "the relay publishes exactly $RELAY_PORT" test "$(published_ports relay)" = "$RELAY_PORT/tcp "
expect "nats mounts exactly its configuration and its TLS pair" test "$(service_secret_files nats)" = "nats.conf nats_server.crt nats_server.key"
expect "the gateway mounts exactly its five secrets" test "$(service_secret_files gateway)" = "agent_ca.crt ca.crt gateway_tls.crt gateway_tls.key nats_gateway_password"
expect "the relay mounts no secret" test -z "$(service_secret_files relay)"
expect "the gateway sits at the address the relay forwards to" test "$(inspect_service gateway '{{(index .NetworkSettings.Networks "ostyr_default").IPAddress}}')" = 172.29.63.11
expect "the relay sits at the address the gateway admits" test "$(inspect_service relay '{{(index .NetworkSettings.Networks "ostyr_default").IPAddress}}')" = 172.29.63.12
expect "the secret files have the expected owners and modes" test "$(remote "cd compose && sudo stat -c '%n %a %u:%g' secrets/gateway_tls.key secrets/nats_gateway_password secrets/nats_admin_password secrets/nats.conf secrets/nats_server.key secrets/agent.key secrets/agent_ca.crt | sed 's#secrets/##' | xargs")" \
    = "gateway_tls.key 600 65534:65534 nats_gateway_password 600 65534:65534 nats_admin_password 600 0:0 nats.conf 600 0:0 nats_server.key 600 0:0 agent.key 600 0:0 agent_ca.crt 644 0:0"
expect "init.sh refuses a nats.conf that lacks the gateway password" remote "sudo rm -rf natsplant && sudo mkdir natsplant && sudo cp -a compose/init.sh natsplant/ && sudo cp -a compose/secrets natsplant/secrets \
    && sudo sh -c 'echo x >natsplant/secrets/nats.conf' && sudo chmod 0600 natsplant/secrets/nats.conf && cd natsplant && ! sudo ./init.sh lab.example 2>&1 | grep -q 'secrets ready' \
    && sudo ./init.sh lab.example 2>&1 | grep -q 'nats.conf does not hold'"
remote "sudo rm -rf natsplant"
expect "the gateway logs that it serves" remote "cd compose && for attempt in \$(seq 1 $LOG_ATTEMPTS); do sudo docker compose logs gateway 2>&1 | grep -q 'serving' && exit 0; sleep 2; done; exit 1"
expect "the relay logs no start error" absent remote "cd compose && sudo docker compose logs relay 2>&1 | grep -e ERROR -e WARN"

nats_box admin nats_admin_password stream add events --subjects "'events.>'" --storage file --retention limits --discard old --max-msgs=-1 --max-bytes=1073741824 \
    --max-age=-1 --max-msg-size=-1 --max-msgs-per-subject=-1 --dupe-window 2m --replicas 1 --no-allow-rollup --no-deny-delete --no-deny-purge >/dev/null
expect "the events stream exists in the events account" nats_box admin nats_admin_password stream info events
expect "the gateway user cannot publish outside events.*" test "$(nats_box gateway nats_gateway_password pub other.subject x 2>&1 | grep -c -i 'permissions violation')" -ge 1
expect "the gateway user cannot call the JetStream API" test "$(nats_box gateway nats_gateway_password pub "'\$JS.API.STREAM.LIST'" x 2>&1 | grep -c -i 'permissions violation')" -ge 1
expect "the gateway user cannot publish on a nested events subject" test "$(nats_box gateway nats_gateway_password pub events.a.b x 2>&1 | grep -c -i 'permissions violation')" -ge 1

remote_bare "sudo mkdir -p $VM_WORK_DIR"
remote_stdin "sudo tee $VM_AGENT_BINARY >/dev/null && sudo chmod 0755 $VM_AGENT_BINARY" <"$AGENT_BINARY"
agent_proofs="$(remote_stdin "cd compose && sudo bash -s -- $VM_AGENT_BINARY secrets $VM_AGENT_DIR" <"$TESTS_DIR/agent-proof.sh")"
printf '%s\n' "$agent_proofs"
agent_value() {
    printf '%s\n' "$agent_proofs" | sed -n "s/^$1 //p"
}
expect "the proof agent sent its batch through the relay port (exit 0)" test "$(agent_value agent_exit)" = 0
expect "the agent run acknowledged one batch" grep -q 'acknowledged 1 batches' <<<"$(agent_value agent_out)"
expect "the spool is empty after the acknowledgement" test "$(agent_value spool_left)" = 0
expect "a client without a certificate reached the gateway through the relay (server certificate received)" test "$(agent_value no_certificate_out)" -ge 1
stream_view="$(NATS_BOX_TTY=-t nats_box admin nats_admin_password stream view events --raw 2>&1 || true)"
printf '%s\n' "$stream_view"
expect "nats stream view shows the batch on events.default" grep -q 't853 batch through the relay' <<<"$stream_view"
stream_messages="$(nats_box admin nats_admin_password stream info events --json | sed -n 's/.*"messages": *\([0-9]*\).*/\1/p' | head -n 1)"
expect "the events stream holds exactly one message" test "$stream_messages" = 1
expect "the gateway logged both refused clients (none, other CA) as failed handshakes" remote "cd compose && for attempt in \$(seq 1 $LOG_ATTEMPTS); do [ \$(sudo docker compose logs gateway 2>&1 | grep -c 'TLS handshake failed') -ge 2 ] && exit 0; sleep 2; done; exit 1"
expect "the gateway published exactly one batch" test "$(remote "cd compose && sudo docker compose logs gateway 2>&1 | grep -c 'a batch was published'")" = 1
remote "cd compose && sudo docker compose logs gateway 2>&1 | tail -n 20"
expect "no event reached the stream from the clients that were refused" test "$(nats_box admin nats_admin_password stream info events --json | sed -n 's/.*"messages": *\([0-9]*\).*/\1/p' | head -n 1)" = 1
expect "a container that is not the relay is dropped by the gateway relay port before the handshake (curl exit 35)" test "$(remote "sudo docker run --rm --network ostyr_default $NATS_BOX_IMAGE curl -sk --max-time 8 -o /dev/null https://172.29.63.11:7443/; echo \$?")" = 35
expect "NATS is closed from the host network" absent remote "nc -z -w 3 $vm_address $NATS_PORT || nc -z -w 3 127.0.0.1 $NATS_PORT"
expect "the gateway ports are closed from the host network" absent remote "nc -z -w 3 127.0.0.1 7444 || nc -z -w 3 $vm_address 7444"
for service_name in postgres platform web playbooks nats gateway relay clickhouse chschema; do
    expect "init.sh refuses the service name $service_name as the public host name" remote "cd compose && sudo ./init.sh $service_name 2>&1 | grep -q 'is a compose service name'"
done
expect "the events stream has the byte limit" test "$(nats_box admin nats_admin_password stream info events --json | sed -n 's/.*"max_bytes": *\([0-9]*\).*/\1/p' | head -n 1)" = 1073741824
expect "the gateway certificate names only DNS:gateway" test "$(remote "cd compose && sudo openssl x509 -in secrets/gateway_tls.crt -noout -ext subjectAltName | grep -c 'DNS:'")" = 1
expect "the gateway key fails curl for the public name (an s_server with the gateway key)" remote "cd compose && (sudo timeout 20 openssl s_server -accept 9555 -www -cert secrets/gateway_tls.crt -key secrets/gateway_tls.key >/dev/null 2>&1 &) ; sleep 2; \
    sudo curl -sS --noproxy '*' --max-time 8 --cacert secrets/ca.crt --resolve lab.example:9555:127.0.0.1 -o /dev/null https://lab.example:9555/ 2>&1 | tee /dev/stderr | grep -q 'no alternative certificate subject name'"
expect "the gateway key is accepted for the name gateway" remote "cd compose && (sudo timeout 20 openssl s_server -accept 9556 -www -cert secrets/gateway_tls.crt -key secrets/gateway_tls.key >/dev/null 2>&1 &) ; sleep 2; \
    sudo curl -sS --noproxy '*' --max-time 8 --cacert secrets/ca.crt --resolve gateway:9556:127.0.0.1 -o /dev/null https://gateway:9556/"
expect "the API key fails the name gateway" remote "cd compose && (sudo timeout 20 openssl s_server -accept 9557 -www -cert secrets/api_tls.crt -key secrets/api_tls.key >/dev/null 2>&1 &) ; sleep 2; \
    sudo curl -sS --noproxy '*' --max-time 8 --cacert secrets/ca.crt --resolve gateway:9557:127.0.0.1 -o /dev/null https://gateway:9557/ 2>&1 | tee /dev/stderr | grep -q 'no alternative certificate subject name'"
expect "chschema finished and exited 0" remote "cd compose && for attempt in \$(seq 1 $LOG_ATTEMPTS); do sudo docker compose ps -a --format '{{.Service}} {{.State}} {{.ExitCode}}' | grep -qx 'chschema exited 0' && exit 0; sleep 2; done; exit 1"
expect "chschema logged its statement count" remote "cd compose && sudo docker compose logs chschema 2>&1 | grep -q 'schema applied: 9 statements'"
expect "chschema runs again with no error (idempotent)" remote "cd compose && sudo docker compose run --rm chschema 2>&1 | grep -q 'schema applied: 9 statements'"
expect "clickhouse is healthy" remote "cd compose && sudo docker compose ps clickhouse --format '{{.Health}}' | grep -qx healthy"
expect "clickhouse publishes no port" absent remote "cd compose && sudo docker compose port clickhouse 8443 | grep -q ."
expect "clickhouse key and users file belong to uid 101 and are mode 600" test "$(remote "cd compose && sudo stat -c '%u %a' secrets/clickhouse_server.key secrets/clickhouse_users | sort -u")" = "101 600"
expect "the ClickHouse certificate names only DNS:clickhouse" test "$(remote "cd compose && sudo openssl x509 -in secrets/clickhouse_server.crt -noout -ext subjectAltName | grep -c 'DNS:clickhouse$'")" = 1
expect "the ClickHouse certificate verifies against the compose CA" remote "cd compose && sudo openssl verify -CAfile secrets/ca.crt secrets/clickhouse_server.crt"
clickhouse_proofs="$(remote_stdin "cd compose && sudo bash -s -- $NATS_BOX_IMAGE" <"$TESTS_DIR/clickhouse-proof.sh")"
printf '%s\n' "$clickhouse_proofs"
clickhouse_value() {
    printf '%s\n' "$clickhouse_proofs" | sed -n "s/^$1 //p"
}
expect "the schema holds 9 objects (6 tables, 3 views)" test "$(clickhouse_value objects)" = 9
expect "the reader reads events (0 rows)" test "$(clickhouse_value reader_select)" = 0
expect "the reader INSERT is refused (497: no grant, and readonly=2 besides)" test "$(clickhouse_value reader_insert_code)" = 497
expect "the reader cannot lift readonly=2 (164)" test "$(clickhouse_value reader_lift_readonly_code)" = 164
expect "the refused INSERT wrote nothing" test "$(clickhouse_value reader_count_after_refused)" = 0
expect "the ingest writer inserts into events" test "$(clickhouse_value ingest_insert)" = 0
expect "the reader sees the ingested row" test "$(clickhouse_value reader_count_after_insert)" = 1
expect "the ingest writer cannot read events (497)" test "$(clickhouse_value ingest_select_code)" = 497
expect "the metrics writer inserts a sample and the rollup view fills" test "$(clickhouse_value metrics_insert)" = 0 -a "$(clickhouse_value rollup_rows)" = 1
expect "the metrics writer cannot read samples and cannot write a rollup (497 and 497)" test "$(clickhouse_value metrics_select_code)/$(clickhouse_value metrics_rollup_insert_code)" = "497/497"
expect "the refused rollup INSERT left the rollup at one row" test "$(clickhouse_value rollup_rows_after_forgery)" = 1
expect "no ClickHouse web page answers (404 for /play, /dashboard, /js)" test "$(clickhouse_value page_play)/$(clickhouse_value page_dashboard)/$(clickhouse_value page_js)" = "404/404/404"
expect "a GET query on / gets 404, only POST is served" test "$(clickhouse_value get_root_select)" = 404
expect "the metrics writer cannot write events (497)" test "$(clickhouse_value metrics_events_code)" = 497
expect "the ingest writer cannot write metrics (497)" test "$(clickhouse_value ingest_metrics_code)" = 497
expect "neither the reader nor the ingest writer can DROP" test "$(clickhouse_value reader_ddl_code)/$(clickhouse_value ingest_ddl_code)" = "497/497"
expect "the reader profile changes only readonly" test "$(clickhouse_value reader_changed_settings)" = "readonly,database,"
expect "the reader runs under readonly=2" test "$(clickhouse_value reader_readonly)" = 2
expect "a wrong password is refused (516)" test "$(clickhouse_value wrong_password_code)" = 516
expect "no default user answers (194 password required, with no and an empty password)" test "$(clickhouse_value default_user_code)/$(clickhouse_value default_empty_password_code)" = "194/194"
expect "the ping answers over verified TLS for the name clickhouse" test "$(clickhouse_value name_check)" = "Ok."
expect "another name fails the certificate check" test "$(clickhouse_value wrong_name)" = 1
expect "plain HTTP 8123 is refused inside the network (curl exit 7)" test "$(clickhouse_value plain_http_8123)" = 7
expect "the native, TLS native, MySQL and PostgreSQL ports are refused (curl exit 7)" test "$(clickhouse_value native_9000)$(clickhouse_value native_tls_9440)$(clickhouse_value mysql_9004)$(clickhouse_value postgres_9005)" = 7777
expect "plain HTTP on the TLS port gets no answer (curl exit not 0)" test "$(clickhouse_value plain_on_tls_port)" != 0
remote "sudo ss -ltnp"

if [[ "$failures" -ne 0 ]]; then
    printf '%s check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'all checks passed\n'
