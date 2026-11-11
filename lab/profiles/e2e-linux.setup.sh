#!/usr/bin/env bash
# Usage: lab/profiles/e2e-linux.setup.sh <lab-state-dir> <lab-prefix>
# Run by up.sh once both VMs answer SSH. First the datastore-pair setup (hosts entries, datastore provisioning, client tools), then the end-to-end
# thread: musl release builds of the Ostyr services, a lab PKI (platform CA, agent CA), settings files, the JetStream stream and the ClickHouse events
# table, systemd units on the datastore VM (event gateway, siem-ingest, detection, alerts API, web UI) and Tetragon plus the Linux agent on the client
# VM. E2E_ONLY=1 skips the datastore-pair part so the script can be run again on a running lab. Every Ostyr service reads settings files only.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly DATASTORE_DOMAIN="datastore.lab.test"
readonly TENANT="lab"
readonly AGENT_ID="agent1"
readonly GATEWAY_PORT=7443
readonly ALERTS_PORT=7444
readonly WEB_PORT=7445
readonly ANALYST_USER="analyst"
readonly ANALYST_PASSWORD="Lab-Analyst-Pass-1"
readonly ADMIN_USER="admin"
readonly ADMIN_PASSWORD="Lab-Admin-Pass-1"
readonly CERT_DAYS=30
readonly MUSL_TARGET="x86_64-unknown-linux-musl"
readonly STORE_KEY_BYTES=32
readonly STREAM_DUPLICATE_WINDOW="10m"
readonly SERVICES=(event-gateway siem-ingest detection alerts-api web-ui)

lab_state="${1:?usage: e2e-linux.setup.sh <lab-state-dir> <lab-prefix>}"
profiles_dir="$(dirname "${BASH_SOURCE[0]}")"
repo_dir="$(cd "$profiles_dir/../.." && pwd)"
PATH="$HOME/.cargo/bin:$PATH"
export PATH

if [[ "${E2E_ONLY:-0}" != "1" ]]; then
    "$profiles_dir/datastore-pair.setup.sh" "$@"
fi

key="$lab_state/id_ed25519"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || die "vms.txt lacks the datastore and client VMs"
ssh_options=(-i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

build_dir="$repo_dir/target/$MUSL_TARGET/release/examples"
log "building the release examples for $MUSL_TARGET"
(cd "$repo_dir" && cargo build --release --target "$MUSL_TARGET" --examples \
    -p event-gateway -p siem-ingest -p detection -p alerts -p web-ui -p agent-linux -p core-auth) >&2

stage="$lab_state/e2e-stage"
rm -rf "$stage"
mkdir -p "$stage/pki" "$stage/datastore/usr/local/bin" "$stage/datastore/etc/ostyr" "$stage/datastore/etc/systemd/system" \
    "$stage/client/usr/local/bin" "$stage/client/etc/ostyr" "$stage/client/etc/systemd/system"
datastore_etc="$stage/datastore/etc/ostyr"
client_etc="$stage/client/etc/ostyr"

make_key() {
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
    chmod 600 "$1"
}

make_ca() {
    local name="$1"
    make_key "$stage/pki/$name.key"
    openssl req -x509 -new -key "$stage/pki/$name.key" -days "$CERT_DAYS" -subj "/CN=ostyr e2e $name" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$stage/pki/$name.pem"
}

make_leaf() {
    local name="$1" ca="$2" subject="$3" extensions="$4"
    make_key "$stage/pki/$name.key"
    openssl req -new -key "$stage/pki/$name.key" -subj "/CN=$subject" -out "$stage/pki/$name.csr"
    printf '%s\n' "$extensions" >"$stage/pki/$name.ext"
    openssl x509 -req -in "$stage/pki/$name.csr" -CA "$stage/pki/$ca.pem" -CAkey "$stage/pki/$ca.key" -CAcreateserial -days "$CERT_DAYS" \
        -extfile "$stage/pki/$name.ext" -out "$stage/pki/$name.crt" 2>/dev/null
}

make_ca platform
make_ca agent
make_leaf server platform "$DATASTORE_DOMAIN" "basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$DATASTORE_DOMAIN,IP:$datastore_address"
make_leaf agent-leaf agent "$AGENT_ID" "basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:urn:ostyr:agent:$TENANT:$AGENT_ID"

install -m 644 "$stage/pki/platform.pem" "$datastore_etc/platform-ca.pem"
install -m 644 "$stage/pki/agent.pem" "$datastore_etc/agent-ca.pem"
install -m 644 "$stage/pki/server.crt" "$datastore_etc/tls.crt"
install -m 600 "$stage/pki/server.key" "$datastore_etc/tls.key"
install -m 644 "$stage/pki/platform.pem" "$client_etc/platform-ca.pem"
install -m 644 "$stage/pki/agent-leaf.crt" "$client_etc/agent.crt"
install -m 600 "$stage/pki/agent-leaf.key" "$client_etc/agent.key"

for binary in event_gateway ingest_run detect alerts_api web_ui; do
    install -m 755 "$build_dir/$binary" "$stage/datastore/usr/local/bin/$binary"
done
install -m 755 "$build_dir/linux_agent" "$stage/client/usr/local/bin/linux_agent"

cat >"$datastore_etc/gateway-server.yaml" <<YAML
listen: "$datastore_address:$GATEWAY_PORT"
certificate: /etc/ostyr/tls.crt
key: /etc/ostyr/tls.key
agent_ca: /etc/ostyr/agent-ca.pem
revocation_file: /etc/ostyr/revoked.yaml
settings_file: /etc/ostyr/channel-settings.yaml
audit_file: /var/lib/ostyr/gateway/channel-audit.log
events_file: /var/lib/ostyr/gateway/unused-events.log
commands_dir: /var/lib/ostyr/gateway/commands
YAML
printf 'revoked_serials: []\n' >"$datastore_etc/revoked.yaml"
printf '{}\n' >"$datastore_etc/channel-settings.yaml"
cat >"$datastore_etc/gateway.yaml" <<YAML
settings_file: /etc/ostyr/gateway-settings.yaml
audit_file: /var/lib/ostyr/gateway/gateway-audit.log
YAML
cat >"$datastore_etc/gateway-settings.yaml" <<YAML
nats_url: "tls://$DATASTORE_DOMAIN:4222"
nats_tls_first: true
nats_ca_file: /etc/ostyr-lab/ca.pem
nats_user: ostyr
nats_password_file: /etc/ostyr/nats.password
YAML

nats_block="nats_url: \"tls://$DATASTORE_DOMAIN:4222\"
nats_tls_first: true
nats_ca_file: /etc/ostyr-lab/ca.pem
nats_user: ostyr
nats_password_file: /etc/ostyr/nats.password
nats_stream: events"
cat >"$datastore_etc/ingest.yaml" <<YAML
clickhouse_url: "https://$DATASTORE_DOMAIN:8443"
clickhouse_database: ostyr
clickhouse_table: events
clickhouse_user: ostyr
clickhouse_password_file: /etc/ostyr/clickhouse.password
clickhouse_ca_file: /etc/ostyr-lab/ca.pem
nats_consumer: siem-ingest
$nats_block
YAML
cat >"$datastore_etc/detection.yaml" <<YAML
audit_file: /var/lib/ostyr/detection/audit.log
checkpoint_dir: /var/lib/ostyr/detection/checkpoints
alerts_file: /var/lib/ostyr/detection/alerts.jsonl
mapping_file: /etc/ostyr/mapping.yaml
rule_files:
  - /etc/ostyr/rules.yaml
sink: postgres
postgres:
  host: $DATASTORE_DOMAIN
  database: ostyr
  user: ostyr
  password_file: /etc/ostyr/postgres.password
  ca_file: /etc/ostyr-lab/ca.pem
ingest:
  nats_consumer: detection
$(sed 's/^/  /' <<<"$nats_block")
YAML
cat >"$datastore_etc/pg.yaml" <<YAML
host: $DATASTORE_DOMAIN
database: ostyr
user: ostyr
password_file: /etc/ostyr/postgres.password
ca_file: /etc/ostyr-lab/ca.pem
YAML
cat >"$datastore_etc/alerts.yaml" <<YAML
name: alerts
version: "1"
tenant: $TENANT
listen: "$datastore_address:$ALERTS_PORT"
settings:
  tls_certificate: /etc/ostyr/tls.crt
  tls_key: /etc/ostyr/tls.key
  accounts_store: /etc/ostyr/accounts.json
  audit_log: /var/lib/ostyr/alerts/audit.log
  key_file: /etc/ostyr/store.key
  compromised_list: /etc/ostyr/compromised.txt
  pg_settings: /etc/ostyr/pg.yaml
YAML
cat >"$datastore_etc/web-ui.yaml" <<YAML
listen: "$datastore_address:$WEB_PORT"
tls:
  certificate: /etc/ostyr/tls.crt
  key: /etc/ostyr/tls.key
api:
  base_url: "https://$DATASTORE_DOMAIN:$ALERTS_PORT"
  ca: /etc/ostyr/platform-ca.pem
  timeout_seconds: 10
audit_file: /var/lib/ostyr/web-ui/audit.log
YAML
cp "$repo_dir/crates/sigma-sql/mappings/ecs.yaml" "$datastore_etc/mapping.yaml"
cat >"$datastore_etc/rules.yaml" <<'YAML'
title: Whoami
id: whoami
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /whoami
  condition: selection
---
title: Whoami seen
id: whoami-seen
correlation:
  type: event_count
  rules:
    - whoami
  timespan: 5m
  condition:
    gte: 1
YAML
printf 'passwordpassword\n' >"$datastore_etc/compromised.txt"
head -c "$STORE_KEY_BYTES" /dev/urandom >"$datastore_etc/store.key"
chmod 600 "$datastore_etc/store.key"

auth_tool="$build_dir/auth_tool"
auth_dir="$stage/auth"
mkdir -p "$auth_dir"
bootstrap_output="$("$auth_tool" "$auth_dir/accounts.json" "$auth_dir/audit.log" "$datastore_etc/store.key" "$datastore_etc/compromised.txt" \
    <<<"bootstrap $ADMIN_USER $ADMIN_PASSWORD")"
totp_secret="$(awk '$1 == "secret" {print $2}' <<<"$bootstrap_output")"
[[ -n "$totp_secret" ]] || die "auth_tool bootstrap printed no TOTP secret"
totp_code="$("$auth_tool" "$auth_dir/accounts.json" "$auth_dir/audit.log" "$datastore_etc/store.key" "$datastore_etc/compromised.txt" <<<"totp $totp_secret")"
coproc AUTH { "$auth_tool" "$auth_dir/accounts.json" "$auth_dir/audit.log" "$datastore_etc/store.key" "$datastore_etc/compromised.txt"; }
printf 'login %s %s 127.0.0.1 %s\n' "$ADMIN_USER" "$ADMIN_PASSWORD" "$totp_code" >&"${AUTH[1]}"
read -r -u "${AUTH[0]}" login_line
admin_token="${login_line##* }"
[[ -n "$admin_token" && "$login_line" != error* ]] || die "auth_tool login failed: $login_line"
printf 'create %s %s %s analyst\n' "$admin_token" "$ANALYST_USER" "$ANALYST_PASSWORD" >&"${AUTH[1]}"
read -r -u "${AUTH[0]}" create_line
[[ "$create_line" != error* ]] || die "auth_tool create failed: $create_line"
auth_input="${AUTH[1]}"
exec {auth_input}>&-
wait "$AUTH_PID" || true
install -m 600 "$auth_dir/accounts.json" "$datastore_etc/accounts.json"

unit() {
    local name="$1" command="$2" extra="${3:-}"
    cat <<UNIT
[Unit]
Description=Ostyr $name (lab)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$command
Restart=always
RestartSec=2
$extra

[Install]
WantedBy=multi-user.target
UNIT
}
datastore_units="$stage/datastore/etc/systemd/system"
unit event-gateway "/usr/local/bin/event_gateway /etc/ostyr/gateway-server.yaml /etc/ostyr/gateway.yaml" >"$datastore_units/ostyr-event-gateway.service"
unit siem-ingest "/usr/local/bin/ingest_run /etc/ostyr/ingest.yaml /run/ostyr-stop-ingest" >"$datastore_units/ostyr-siem-ingest.service"
unit detection "/usr/local/bin/detect /etc/ostyr/detection.yaml /run/ostyr-stop-detection" >"$datastore_units/ostyr-detection.service"
unit alerts-api "/usr/local/bin/alerts_api /etc/ostyr/alerts.yaml" >"$datastore_units/ostyr-alerts-api.service"
unit web-ui "/usr/local/bin/web_ui /etc/ostyr/web-ui.yaml" >"$datastore_units/ostyr-web-ui.service"

cat >"$client_etc/agent.yaml" <<YAML
server: "$datastore_address:$GATEWAY_PORT"
server_name: $DATASTORE_DOMAIN
certificate: /etc/ostyr/agent.crt
key: /etc/ostyr/agent.key
platform_ca: /etc/ostyr/platform-ca.pem
tenant: $TENANT
agent_id: $AGENT_ID
keys_file: /etc/ostyr/command-keys.yaml
state_file: /var/lib/ostyr-agent/command-state
audit_file: /var/lib/ostyr-agent/channel-audit.log
spool_file: /var/lib/ostyr-agent/spool
sequence_file: /var/lib/ostyr-agent/sequence
executed_file: /var/lib/ostyr-agent/executed
YAML
printf 'keys: []\n' >"$client_etc/command-keys.yaml"
cat >"$client_etc/linux.yaml" <<YAML
agent_file: /etc/ostyr/agent.yaml
export_path: /var/log/tetragon/tetragon.log
cursor_file: /var/lib/ostyr-agent/source/cursor
audit_file: /var/lib/ostyr-agent/linux-audit.log
sensor:
  window_seconds: 240
  interval_seconds: 30
  max_restarts_per_hour: 0
YAML
unit linux-agent "/usr/local/bin/linux_agent /etc/ostyr/linux.yaml" >"$stage/client/etc/systemd/system/ostyr-linux-agent.service"

tetragon_tarball="$("$repo_dir/lab/tetragon-fetch.sh")"

datastore_target="$datastore_user@$datastore_address"
client_target="$client_user@$client_address"

log "installing on the datastore VM"
tar -C "$stage/datastore" --owner=0 --group=0 -cf - . | ssh "${ssh_options[@]}" "$datastore_target" "sudo tar -C / -xpf -"
scp "${ssh_options[@]}" "$repo_dir/lab/tests/fixtures/e2e-events.sql" "$datastore_target:/tmp/e2e-events.sql"
ssh "${ssh_options[@]}" "$datastore_target" "sudo bash -s $STREAM_DUPLICATE_WINDOW" <<'REMOTE'
set -euo pipefail
duplicate_window="$1"
source /etc/ostyr-lab/datastore.env
install -d -m 700 /var/lib/ostyr /var/lib/ostyr/gateway /var/lib/ostyr/gateway/commands /var/lib/ostyr/detection /var/lib/ostyr/detection/checkpoints \
    /var/lib/ostyr/alerts /var/lib/ostyr/web-ui
printf '%s' "$NATS_PASSWORD" >/etc/ostyr/nats.password
printf '%s' "$CLICKHOUSE_PASSWORD" >/etc/ostyr/clickhouse.password
printf '%s' "$POSTGRES_PASSWORD" >/etc/ostyr/postgres.password
chmod 600 /etc/ostyr/nats.password /etc/ostyr/clickhouse.password /etc/ostyr/postgres.password
clickhouse() {
    curl --fail --silent --show-error --cacert "$DATASTORE_CA" --user "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" --data-binary "$1" \
        "https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT/"
}
clickhouse 'CREATE DATABASE IF NOT EXISTS ostyr'
clickhouse "$(cat /tmp/e2e-events.sql)"
rm -f /tmp/e2e-events.sql
nats() {
    /usr/local/share/ostyr-lab/client/nats --server "tls://$DATASTORE_DOMAIN:$NATS_PORT" --tlsfirst --tlsca "$DATASTORE_CA" --user "$NATS_USER" \
        --password "$NATS_PASSWORD" "$@"
}
nats stream info events >/dev/null 2>&1 || nats stream add events --subjects 'events.>,dead.events' --storage file --retention limits --discard old \
    --max-msgs=-1 --max-bytes=-1 --max-age=-1 --max-msg-size=-1 --max-msgs-per-subject=-1 --dupe-window "$duplicate_window" --replicas 1 \
    --no-allow-rollup --no-deny-delete --no-deny-purge >/dev/null
REMOTE
ssh -n "${ssh_options[@]}" "$datastore_target" "sudo systemctl daemon-reload && sudo systemctl enable --now ${SERVICES[*]/#/ostyr-}" >/dev/null 2>&1 ||
    die "enabling the Ostyr services failed on the datastore VM"

log "installing Tetragon and the Linux agent on the client VM"
scp "${ssh_options[@]}" "$tetragon_tarball" "$client_target:/tmp/tetragon.tar.gz"
tar -C "$stage/client" --owner=0 --group=0 -cf - . | ssh "${ssh_options[@]}" "$client_target" "sudo tar -C / -xpf -"
ssh "${ssh_options[@]}" "$client_target" "sudo bash -s" <<'REMOTE'
set -euo pipefail
install -d -m 700 /var/lib/ostyr-agent /var/lib/ostyr-agent/source
install -d -m 700 /tmp/tetragon-release
tar -C /tmp/tetragon-release -xzf /tmp/tetragon.tar.gz
/tmp/tetragon-release/tetragon-v1.8.0-amd64/install.sh >/dev/null
printf '%s' '{"event_set":["PROCESS_EXEC"]}' >/etc/tetragon/tetragon.conf.d/export-allowlist
printf 'false' >/etc/tetragon/tetragon.conf.d/export-file-compress
rm -rf /tmp/tetragon-release /tmp/tetragon.tar.gz
systemctl restart tetragon
systemctl daemon-reload
systemctl enable --now ostyr-linux-agent
REMOTE
log "e2e-linux setup done"
