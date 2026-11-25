#!/usr/bin/env bash
# Usage: sudo bash -s -- <channel_agent binary> <secrets dir> <work dir> < agent-proof.sh
# Runs inside the lab VM, in the compose directory. The proof agent (certificate from init.sh) sends one spooled batch to the published relay port, then
# two clients without a usable certificate (none, and one from another CA) are refused by the gateway behind the relay. Prints `key value` lines.
set -euo pipefail

agent_binary="${1:?usage: agent-proof.sh <channel_agent> <secrets dir> <work dir>}"
secrets_dir="${2:?secrets dir}"
work_dir="${3:?work dir}"
readonly agent_binary secrets_dir work_dir
readonly RELAY_ADDRESS=127.0.0.1:7443
readonly RUN_TIMEOUT_SECONDS=60
readonly HANDSHAKE_TIMEOUT_SECONDS=15
readonly HOST_EVENT_HEAD='{"ecs":{"version":"8.11.0"},"event":{"kind":"metric","category":["host"],"type":["info"],"dataset":"ostyr.host_metrics"},"host":{"name":"lab-host"},"@timestamp":'
readonly HOST_EVENT_TAIL=',"metrics":{"system.cpu.utilization":0.97},"metrics_omitted":0,"metrics_failed":0}'
readonly EVENT='{"@timestamp":"2026-11-24T00:00:00Z","ecs":{"version":"8.11.0"},"event":{"kind":"event","dataset":"lab.proof"},"message":"t853 batch through the relay"}'

rm -rf "$work_dir"
install -d -m 0700 "$work_dir"
install -m 0644 "$secrets_dir/agent.crt" "$secrets_dir/ca.crt" "$work_dir/"
install -m 0600 "$secrets_dir/agent.key" "$work_dir/"
printf 'keys: []\n' >"$work_dir/command-keys.yaml"
cat >"$work_dir/agent.yaml" <<YAML
server: "$RELAY_ADDRESS"
server_name: gateway
certificate: $work_dir/agent.crt
key: $work_dir/agent.key
platform_ca: $work_dir/ca.crt
tenant: default
agent_id: lab-agent
keys_file: $work_dir/command-keys.yaml
state_file: $work_dir/command-state
audit_file: $work_dir/channel-audit.log
spool_file: $work_dir/spool
sequence_file: $work_dir/sequence
executed_file: $work_dir/executed
YAML
host_stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s\n' "$EVENT" "${HOST_EVENT_HEAD}\"${host_stamp}\"${HOST_EVENT_TAIL}" >"$work_dir/spool"

agent_status=0
timeout "$RUN_TIMEOUT_SECONDS" "$agent_binary" "$work_dir/agent.yaml" 1 >"$work_dir/agent.out" 2>"$work_dir/agent.err" || agent_status=$?
printf 'agent_exit %s\n' "$agent_status"
printf 'agent_out %s\n' "$(grep -m1 '^run 0:' "$work_dir/agent.out" || true)"
spool_left=0
if [[ -e "$work_dir/spool" ]]; then
    spool_left="$(wc -c <"$work_dir/spool")"
fi
printf 'spool_left %s\n' "$spool_left"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=other agent" \
    -addext "subjectAltName=URI:urn:ostyr:agent:default:lab-agent" -keyout "$work_dir/other.key" -out "$work_dir/other.crt" 2>/dev/null

no_certificate_status=0
timeout "$HANDSHAKE_TIMEOUT_SECONDS" openssl s_client -connect "$RELAY_ADDRESS" -tls1_3 -servername gateway -CAfile "$work_dir/ca.crt" \
    -verify_return_error </dev/null >"$work_dir/no-cert.out" 2>&1 || no_certificate_status=$?
printf 'no_certificate_exit %s\n' "$no_certificate_status"
printf 'no_certificate_out %s\n' "$(grep -c 'BEGIN CERTIFICATE' "$work_dir/no-cert.out" || true)"

other_status=0
timeout "$HANDSHAKE_TIMEOUT_SECONDS" openssl s_client -connect "$RELAY_ADDRESS" -tls1_3 -servername gateway -CAfile "$work_dir/ca.crt" \
    -cert "$work_dir/other.crt" -key "$work_dir/other.key" -verify_return_error </dev/null >"$work_dir/other-cert.out" 2>&1 || other_status=$?
printf 'other_ca_exit %s\n' "$other_status"
