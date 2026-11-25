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
readonly GATEWAY_DIRECT_PORT=7446
readonly RELAY_PORT=7442
readonly RELAY_NOFILE=4096
readonly ALERTS_PORT=7444
readonly WEB_PORT=7445
readonly ANALYST_USER="analyst"
readonly ANALYST_PASSWORD="Lab-Analyst-Pass-1"
readonly ADMIN_USER="admin"
readonly ADMIN_PASSWORD="Lab-Admin-Pass-1"
readonly CERT_DAYS=30
readonly MUSL_TARGET="x86_64-unknown-linux-musl"
readonly STORE_KEY_BYTES=32
readonly STREAM_DUPLICATE_WINDOW_NS=600000000000
readonly CONSUMER_ACK_WAIT="30s"
readonly SERVICES=(event-gateway relay siem-ingest detection alerts-api web-ui)

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
    -p siem-ingest -p detection -p alerts -p agent-linux) >&2
(cd "$repo_dir" && cargo build --release --target "$MUSL_TARGET" --bin ostyr-web-ui --bin ostyr-auth --bin ostyr-event-gateway --bin ostyr-siem-ingest --bin ostyr-relay --bin ostyr-detect -p detection -p web-ui -p core-auth -p event-gateway -p siem-ingest -p relay) >&2
bin_dir="$repo_dir/target/$MUSL_TARGET/release"

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
for name in gateway alerts web; do
    install -m 600 "$stage/pki/server.key" "$datastore_etc/tls-$name.key"
done
install -m 644 "$stage/pki/platform.pem" "$client_etc/platform-ca.pem"
install -m 644 "$stage/pki/agent-leaf.crt" "$client_etc/agent.crt"
install -m 600 "$stage/pki/agent-leaf.key" "$client_etc/agent.key"

for binary in alerts_api; do
    install -m 755 "$build_dir/$binary" "$stage/datastore/usr/local/bin/$binary"
done
install -m 755 "$bin_dir/ostyr-detect" "$stage/datastore/usr/local/bin/ostyr-detect"
install -m 755 "$bin_dir/ostyr-web-ui" "$stage/datastore/usr/local/bin/ostyr-web-ui"
install -m 755 "$bin_dir/ostyr-siem-ingest" "$stage/datastore/usr/local/bin/ostyr-siem-ingest"
install -m 755 "$bin_dir/ostyr-event-gateway" "$stage/datastore/usr/local/bin/ostyr-event-gateway"
install -m 755 "$bin_dir/ostyr-relay" "$stage/datastore/usr/local/bin/ostyr-relay"
install -m 755 "$build_dir/linux_agent" "$stage/client/usr/local/bin/linux_agent"

cat >"$datastore_etc/gateway-server.yaml" <<YAML
listen: "127.0.0.1:$GATEWAY_DIRECT_PORT"
relay_listen: "$datastore_address:$GATEWAY_PORT"
certificate: /etc/ostyr/tls.crt
key: /etc/ostyr/tls-gateway.key
agent_ca: /etc/ostyr/agent-ca.pem
revocation_file: /etc/ostyr/revoked.yaml
settings_file: /etc/ostyr/channel-settings.yaml
audit_file: /var/lib/ostyr/gateway/channel-audit.log
events_file: /var/lib/ostyr/gateway/unused-events.log
commands_dir: /var/lib/ostyr/gateway/commands
YAML
printf 'revoked_serials: []\n' >"$datastore_etc/revoked.yaml"
printf 'relay_sources: [%s]\n' "${E2E_RELAY_SOURCE:-$datastore_address}" >"$datastore_etc/channel-settings.yaml"
cat >"$datastore_etc/relay.yaml" <<YAML
listen: "$datastore_address:$RELAY_PORT"
upstream: "$datastore_address:$GATEWAY_PORT"
YAML
cat >"$datastore_etc/gateway.yaml" <<YAML
settings_file: /etc/ostyr/gateway-settings.yaml
audit_file: /var/lib/ostyr/gateway/gateway-audit.log
YAML
cat >"$datastore_etc/gateway-settings.yaml" <<YAML
nats_url: "tls://$DATASTORE_DOMAIN:4222"
nats_tls_first: true
nats_ca_file: /etc/ostyr-lab/ca.pem
nats_user: gateway
nats_password_file: /etc/ostyr/nats-gateway.password
YAML

nats_block() {
    cat <<BLOCK
nats_url: "tls://$DATASTORE_DOMAIN:4222"
nats_tls_first: true
nats_ca_file: /etc/ostyr-lab/ca.pem
nats_user: $1
nats_password_file: /etc/ostyr/nats-$2.password
nats_stream: events
BLOCK
}
cat >"$datastore_etc/ingest.yaml" <<YAML
clickhouse_url: "https://$DATASTORE_DOMAIN:8443"
clickhouse_database: ostyr
clickhouse_table: events
clickhouse_user: ostyr
clickhouse_password_file: /etc/ostyr/clickhouse.password
clickhouse_ca_file: /etc/ostyr-lab/ca.pem
audit_file: /var/lib/ostyr/siem-ingest/audit.log
nats_consumer: siem-ingest
$(nats_block siem_ingest siem-ingest)
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
  password_file: /etc/ostyr/postgres-detection.password
  ca_file: /etc/ostyr-lab/ca.pem
ingest:
  nats_consumer: detection
$(nats_block detection detection | sed 's/^/  /')
YAML
cat >"$datastore_etc/pg.yaml" <<YAML
host: $DATASTORE_DOMAIN
database: ostyr
user: ostyr
password_file: /etc/ostyr/postgres-alerts.password
ca_file: /etc/ostyr-lab/ca.pem
YAML
cat >"$datastore_etc/alerts.yaml" <<YAML
name: alerts
version: "1"
tenant: $TENANT
listen: "$datastore_address:$ALERTS_PORT"
settings:
  tls_certificate: /etc/ostyr/tls.crt
  tls_key: /etc/ostyr/tls-alerts.key
  accounts_store: /var/lib/ostyr/alerts/accounts.json
  audit_log: /var/lib/ostyr/alerts/audit.log
  key_file: /etc/ostyr/store.key
  compromised_list: /etc/ostyr/compromised.txt
  pg_settings: /etc/ostyr/pg.yaml
YAML
cat >"$datastore_etc/web-ui.yaml" <<YAML
listen: "$datastore_address:$WEB_PORT"
tls:
  certificate: /etc/ostyr/tls.crt
  key: /etc/ostyr/tls-web.key
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

auth_tool="$bin_dir/ostyr-auth"
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
unit event-gateway "/usr/local/bin/ostyr-event-gateway /etc/ostyr/gateway-server.yaml /etc/ostyr/gateway.yaml" "User=ostyr-gateway" >"$datastore_units/ostyr-event-gateway.service"
unit relay "/usr/local/bin/ostyr-relay /etc/ostyr/relay.yaml /var/lib/ostyr/relay/relay-audit.log" "User=ostyr-relay
LimitNOFILE=$RELAY_NOFILE
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/ostyr/relay" >"$datastore_units/ostyr-relay.service"
unit siem-ingest "/usr/local/bin/ostyr-siem-ingest /etc/ostyr/ingest.yaml" "User=ostyr-siem" >"$datastore_units/ostyr-siem-ingest.service"
unit detection "/usr/local/bin/ostyr-detect /etc/ostyr/detection.yaml" "User=ostyr-detection" >"$datastore_units/ostyr-detection.service"
unit alerts-api "/usr/local/bin/alerts_api /etc/ostyr/alerts.yaml" "User=ostyr-alerts" >"$datastore_units/ostyr-alerts-api.service"
unit web-ui "/usr/local/bin/ostyr-web-ui /etc/ostyr/web-ui.yaml" "User=ostyr-web" >"$datastore_units/ostyr-web-ui.service"

cat >"$client_etc/agent.yaml" <<YAML
server: "$datastore_address:$GATEWAY_DIRECT_PORT"
relays:
  - "$datastore_address:$RELAY_PORT"
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
ssh "${ssh_options[@]}" "$datastore_target" "sudo bash -s $STREAM_DUPLICATE_WINDOW_NS $CONSUMER_ACK_WAIT" <<'REMOTE'
set -euo pipefail
duplicate_window_ns="$1"
ACK_WAIT="$2"
source /etc/ostyr-lab/datastore.env
for service_user in ostyr-gateway ostyr-relay ostyr-siem ostyr-detection ostyr-alerts ostyr-web; do
    id "$service_user" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$service_user"
done
install -d -m 755 /var/lib/ostyr
install -d -m 700 -o ostyr-gateway /var/lib/ostyr/gateway /var/lib/ostyr/gateway/commands
install -d -m 700 -o ostyr-relay /var/lib/ostyr/relay
install -d -m 700 -o ostyr-siem /var/lib/ostyr/siem-ingest
install -d -m 700 -o ostyr-detection /var/lib/ostyr/detection /var/lib/ostyr/detection/checkpoints
install -d -m 700 -o ostyr-alerts /var/lib/ostyr/alerts
install -d -m 700 -o ostyr-web /var/lib/ostyr/web-ui
secret_file() {
    install -m 400 -o "$2" -g "$2" /dev/null "$3"
    printf '%s' "$1" >"$3"
}
secret_file "$NATS_GATEWAY_PASSWORD" ostyr-gateway /etc/ostyr/nats-gateway.password
secret_file "$NATS_INGEST_PASSWORD" ostyr-siem /etc/ostyr/nats-siem-ingest.password
secret_file "$NATS_DETECTION_PASSWORD" ostyr-detection /etc/ostyr/nats-detection.password
secret_file "$CLICKHOUSE_PASSWORD" ostyr-siem /etc/ostyr/clickhouse.password
secret_file "$POSTGRES_PASSWORD" ostyr-detection /etc/ostyr/postgres-detection.password
secret_file "$POSTGRES_PASSWORD" ostyr-alerts /etc/ostyr/postgres-alerts.password
for name in gateway alerts web; do
    chown "ostyr-$name:ostyr-$name" "/etc/ostyr/tls-$name.key"
    chmod 400 "/etc/ostyr/tls-$name.key"
done
install -m 600 -o ostyr-alerts -g ostyr-alerts /etc/ostyr/accounts.json /var/lib/ostyr/alerts/accounts.json
rm -f /etc/ostyr/accounts.json
chown ostyr-alerts:ostyr-alerts /etc/ostyr/store.key
chmod 600 /etc/ostyr/store.key
clickhouse() {
    curl --fail --silent --show-error --cacert "$DATASTORE_CA" --user "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" --data-binary "$1" \
        "https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT/"
}
clickhouse 'CREATE DATABASE IF NOT EXISTS ostyr'
clickhouse "$(cat /tmp/e2e-events.sql)"
rm -f /tmp/e2e-events.sql
export NATS_PASSWORD
nats() {
    /usr/local/share/ostyr-lab/client/nats --server "tls://$DATASTORE_DOMAIN:$NATS_PORT" --tlsfirst --tlsca "$DATASTORE_CA" --user "$NATS_USER" "$@"
}
stream_die() {
    echo "stream $1: $2" >&2
    exit 1
}
stream_check() {
    nats request "\$JS.API.STREAM.INFO.$1" '' --raw | python3 -I -c '
import json, sys
config = json.load(sys.stdin)["config"]
subject, max_msgs, max_bytes, max_msg_size, per_subject, window = sys.argv[1:]
expected = {"subjects": [subject], "retention": "limits", "max_consumers": -1, "max_msgs_per_subject": int(per_subject),
            "max_msgs": int(max_msgs), "max_bytes": int(max_bytes), "max_age": 0, "max_msg_size": int(max_msg_size), "storage": "file",
            "discard": "old", "num_replicas": 1, "duplicate_window": int(window), "sealed": False, "deny_delete": False, "deny_purge": False,
            "allow_rollup_hdrs": False, "allow_direct": True, "mirror_direct": False, "consumer_limits": {},
            "compression": "none", "allow_msg_ttl": False}
actual = {key: value for key, value in config.items() if key != "name"}
server_metadata = ("_nats.ver", "_nats.level", "_nats.req.level")
operator_metadata = {key: value for key, value in actual.pop("metadata", {}).items() if key not in server_metadata}
if operator_metadata:
    actual["metadata"] = operator_metadata
def dump(table, key):
    return json.dumps(table[key], sort_keys=True) if key in table else None
bad = sorted(key for key in set(actual) | set(expected) if dump(actual, key) != dump(expected, key))
if bad:
    sys.exit(" ".join(bad))
' "${@:2}" || stream_die "$1" "the stored configuration differs from the expected one on the fields above (the script never deletes data: delete and recreate the stream)"
}
add_stream() {
    nats stream info "$1" >/dev/null 2>&1 || nats stream add "$1" --subjects "$2" --storage file --retention limits --discard old \
        --max-msgs=-1 --max-bytes=-1 --max-age=-1 --max-msg-size=-1 --max-msgs-per-subject=-1 --dupe-window "${duplicate_window_ns}ns" --replicas 1 \
        --no-allow-rollup --no-deny-delete --no-deny-purge >/dev/null
    stream_check "$1" "$2" -1 -1 -1 -1 "$duplicate_window_ns"
}
add_durable() {
    nats consumer info events "$1" >/dev/null 2>&1 || nats consumer add events "$1" --pull --deliver all --ack explicit --filter 'events.>' --replay instant \
        --max-deliver=-1 --max-pending 1000 --no-headers-only --wait "$ACK_WAIT" --defaults >/dev/null
    nats request "\$JS.API.CONSUMER.INFO.events.$1" '' --raw | python3 -I -c '
import json, sys
config = json.load(sys.stdin)["config"]
durable, ack_wait = sys.argv[1:]
expected = {"durable_name": durable, "deliver_policy": "all", "ack_policy": "explicit", "ack_wait": int(ack_wait.rstrip("s")) * 1000000000,
            "max_deliver": -1, "filter_subject": "events.>", "replay_policy": "instant", "max_waiting": 512, "max_ack_pending": 1000,
            "num_replicas": 0, "pause_until": "0001-01-01T00:00:00Z"}
actual = {key: value for key, value in config.items() if key != "name"}
server_metadata = ("_nats.ver", "_nats.level", "_nats.req.level")
operator_metadata = {key: value for key, value in actual.pop("metadata", {}).items() if key not in server_metadata}
if operator_metadata:
    actual["metadata"] = operator_metadata
def dump(table, key):
    return json.dumps(table[key], sort_keys=True) if key in table else None
bad = sorted(key for key in set(actual) | set(expected) if dump(actual, key) != dump(expected, key))
if bad:
    sys.exit(" ".join(bad))
' "$1" "$ACK_WAIT" || stream_die events "durable $1 differs from the expected configuration on the fields above (delete and recreate the durable)"
}
add_stream events 'events.>'
readonly DEAD_TENANT_BUDGET=16 DEAD_MAX_MSGS_PER_TENANT=1000 DEAD_MAX_MSG_SIZE=8192 DEAD_MAX_MSGS=16000 DEAD_MAX_BYTES=134217728
dead_die() {
    stream_die dead "$*"
}
((DEAD_MAX_BYTES >= DEAD_MAX_MSGS_PER_TENANT * DEAD_MAX_MSG_SIZE * DEAD_TENANT_BUDGET)) || dead_die "DEAD_MAX_BYTES is below the per-tenant budget"
((DEAD_MAX_MSGS >= DEAD_MAX_MSGS_PER_TENANT * DEAD_TENANT_BUDGET)) || dead_die "DEAD_MAX_MSGS is below the per-tenant budget"
dead_limits=(--subjects 'dead.events.*' --max-msgs="$DEAD_MAX_MSGS" --max-bytes="$DEAD_MAX_BYTES" --max-age=0 --max-msg-size="$DEAD_MAX_MSG_SIZE"
    --max-msgs-per-subject="$DEAD_MAX_MSGS_PER_TENANT")
dead_settings=(--discard old --dupe-window "${duplicate_window_ns}ns" --replicas 1 --no-allow-rollup --no-deny-delete --no-deny-purge)
add_dead_stream() {
    if nats stream info dead >/dev/null 2>&1; then
        nats stream edit dead --force "${dead_limits[@]}" "${dead_settings[@]}" >/dev/null
    else
        nats stream add dead "${dead_limits[@]}" "${dead_settings[@]}" --storage file --retention limits >/dev/null
    fi
    stream_check dead 'dead.events.*' "$DEAD_MAX_MSGS" "$DEAD_MAX_BYTES" "$DEAD_MAX_MSG_SIZE" "$DEAD_MAX_MSGS_PER_TENANT" "$duplicate_window_ns"
}
add_dead_stream
for durable in siem-ingest detection metrics-ingest; do
    add_durable "$durable"
done
REMOTE
ssh -n "${ssh_options[@]}" "$datastore_target" "sudo systemctl daemon-reload && sudo systemctl enable ${SERVICES[*]/#/ostyr-} && sudo systemctl restart ${SERVICES[*]/#/ostyr-}" >/dev/null 2>&1 ||
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
printf 'true' >/etc/tetragon/tetragon.conf.d/enable-process-cred
rm -rf /tmp/tetragon-release /tmp/tetragon.tar.gz
systemctl restart tetragon
systemctl daemon-reload
systemctl enable ostyr-linux-agent
systemctl restart ostyr-linux-agent
REMOTE
log "e2e-linux setup done"
