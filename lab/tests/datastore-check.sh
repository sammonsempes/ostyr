#!/usr/bin/env bash
# Usage: lab/tests/datastore-check.sh <task-id>
# On a booted datastore-pair lab: from the client VM, inserts and reads back a ClickHouse row over TLS, publishes and consumes (with ack) a JetStream
# message, and runs a PostgreSQL query over TLS; checks that plaintext access is refused; then, from the host, that no datastore port answers on
# the host loopback or LAN address and that the datastore itself has no route out. A marker of the previous run kept in the lab state directory is
# read back from all three stores, which proves persistence after a reboot of the datastore VM. Prints "ok" per check.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly CONNECT_TIMEOUT=3
readonly MARKER_BYTES=8
readonly LAB_PORTS=(8443 9440 4222 5432 3910)
readonly PLAINTEXT_PORTS=(8123 9000 9004 9005 9009)

task_id="${1:?usage: datastore-check.sh <task-id>}"
lab_state="$(state_dir "$task_id")"
marker_file="$lab_state/datastore-check.marker"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$datastore_address" && -n "$client_address" ]] || die "vms.txt lacks the datastore and client VMs"
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

marker="$(openssl rand -hex "$MARKER_BYTES")"
previous_marker=""
[[ ! -s "$marker_file" ]] || previous_marker="$(cat "$marker_file")"

ssh "${ssh_options[@]}" "$client_user@$client_address" "sudo bash -s '$marker' '$previous_marker'" <<'REMOTE'
set -euo pipefail
marker="$1"
previous_marker="$2"
source /etc/ostyr-lab/datastore.env
step() { printf 'ok %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1" >&2; exit 1; }

clickhouse() {
    curl --fail --silent --show-error --cacert "$DATASTORE_CA" --user "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" --data-binary "$1" \
        "https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT/"
}
postgres() {
    PGPASSWORD="$POSTGRES_PASSWORD" psql "host=$DATASTORE_DOMAIN port=$POSTGRES_PORT user=$POSTGRES_USER dbname=$POSTGRES_DATABASE sslmode=verify-full sslrootcert=$DATASTORE_CA" \
        --tuples-only --no-align --quiet -c "$1"
}
jetstream() {
    nats --server "tls://$DATASTORE_DOMAIN:$NATS_PORT" --tlsfirst --tlsca "$DATASTORE_CA" --user "$NATS_USER" --password "$NATS_PASSWORD" "$@"
}

clickhouse 'CREATE TABLE IF NOT EXISTS default.ostyr_check (marker String) ENGINE = MergeTree ORDER BY marker' >/dev/null
clickhouse "INSERT INTO default.ostyr_check VALUES ('$marker')"
[[ "$(clickhouse "SELECT marker FROM default.ostyr_check WHERE marker = '$marker'")" == "$marker" ]] || fail "ClickHouse row not read back"
step "ClickHouse insert and read back over TLS"

postgres 'CREATE TABLE IF NOT EXISTS ostyr_check (marker text)' >/dev/null
postgres "INSERT INTO ostyr_check VALUES ('$marker')" >/dev/null
[[ "$(postgres "SELECT marker FROM ostyr_check WHERE marker = '$marker'")" == "$marker" ]] || fail "PostgreSQL row not read back"
[[ "$(postgres 'SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()')" == "t" ]] || fail "PostgreSQL session is not TLS"
step "PostgreSQL query over TLS"

jetstream stream info OSTYR_CHECK >/dev/null 2>&1 || jetstream stream add OSTYR_CHECK --subjects 'ostyr.check.>' --storage file --retention limits \
    --discard old --max-msgs=-1 --max-bytes=-1 --max-age=-1 --max-msg-size=-1 --max-msgs-per-subject=-1 --dupe-window 2m --replicas 1 \
    --no-allow-rollup --no-deny-delete --no-deny-purge >/dev/null
jetstream consumer add OSTYR_CHECK "check-$marker" --pull --deliver new --ack explicit --filter "ostyr.check.$marker" --replay instant \
    --max-deliver=-1 --max-pending 100 --no-headers-only --wait 30s --defaults >/dev/null
jetstream pub "ostyr.check.$marker" "$marker" >/dev/null
received="$(jetstream consumer next OSTYR_CHECK "check-$marker" --ack --raw 2>/dev/null || true)"
[[ "$received" == "$marker" ]] || fail "JetStream message not consumed, got '$received'"
[[ "$(jetstream consumer info OSTYR_CHECK "check-$marker" --json | jq -r '.num_ack_pending + .num_pending')" == "0" ]] || fail "JetStream ack not recorded"
step "JetStream publish, consume and ack over TLS"

s3_access="$(cat "$S3_ACCESS_FILE")"
s3_secret="$(cat "$S3_SECRET_FILE")"
s3() {
    curl --fail --silent --show-error --cacert "$DATASTORE_CA" --user "$s3_access:$s3_secret" --aws-sigv4 "aws:amz:$S3_REGION:s3" "$@"
}
s3_url="$S3_ENDPOINT/$S3_BUCKET/check-$marker"
s3 --request PUT --data-binary "$marker" --output /dev/null "$s3_url"
[[ "$(s3 "$s3_url")" == "$marker" ]] || fail "S3 object not read back"
if curl --silent --max-time 3 --cacert "$DATASTORE_CA" --user "$s3_access:wrong" --aws-sigv4 "aws:amz:$S3_REGION:s3" --fail "$s3_url" >/dev/null; then
    fail "S3 accepts a wrong secret"
fi
step "S3 signed PUT and GET over TLS with the lab CA"

if [[ -n "$previous_marker" ]]; then
    [[ "$(clickhouse "SELECT marker FROM default.ostyr_check WHERE marker = '$previous_marker'")" == "$previous_marker" ]] || fail "previous ClickHouse row lost"
    [[ "$(postgres "SELECT marker FROM ostyr_check WHERE marker = '$previous_marker'")" == "$previous_marker" ]] || fail "previous PostgreSQL row lost"
    [[ "$(jetstream stream get OSTYR_CHECK --last-for "ostyr.check.$previous_marker" --json | jq -r '.data' | base64 -d)" == "$previous_marker" ]] ||
        fail "previous JetStream message lost"
    [[ "$(s3 "$S3_ENDPOINT/$S3_BUCKET/check-$previous_marker")" == "$previous_marker" ]] || fail "previous S3 object lost"
    step "data of the previous run persisted in all four stores"
fi

if curl --silent --max-time 3 "http://$DATASTORE_DOMAIN:8123/ping" >/dev/null; then fail "ClickHouse answers in plaintext on 8123"; fi
if PGPASSWORD="$POSTGRES_PASSWORD" psql "host=$DATASTORE_DOMAIN port=$POSTGRES_PORT user=$POSTGRES_USER dbname=$POSTGRES_DATABASE sslmode=disable" -c 'SELECT 1' >/dev/null 2>&1; then
    fail "PostgreSQL accepts a plaintext session"
fi
if curl --silent --max-time 3 --user "$CLICKHOUSE_USER:wrong" --data-binary 'SELECT 1' --cacert "$DATASTORE_CA" "https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT/" | grep -qx 1; then
    fail "ClickHouse accepts a wrong password"
fi
step "plaintext and wrong-password access refused"
REMOTE
printf '%s\n' "$marker" >"$marker_file"

port_answers() {
    timeout "$CONNECT_TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}
host_lan_address="$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
[[ -n "$host_lan_address" ]] || die "cannot find the host LAN address"
for address in 127.0.0.1 "$host_lan_address"; do
    for port in "${LAB_PORTS[@]}" "${PLAINTEXT_PORTS[@]}"; do
        if port_answers "$address" "$port"; then
            die "port $port answers on host address $address"
        fi
    done
done
printf 'ok no datastore port answers on the host loopback or LAN address\n'

for port in "${PLAINTEXT_PORTS[@]}"; do
    if port_answers "$datastore_address" "$port"; then
        die "plaintext port $port answers on the lab address"
    fi
done
for port in "${LAB_PORTS[@]}"; do
    port_answers "$datastore_address" "$port" || die "TLS port $port does not answer on the lab address"
done
printf 'ok only the TLS ports answer on the lab address\n'

listeners="$(ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "ss -Hltn")"
for port in "${LAB_PORTS[@]}"; do
    awk -v port="$port" '$4 ~ ":" port "$" {print $4}' <<<"$listeners" | grep -qx "$datastore_address:$port" || die "port $port is not bound to $datastore_address"
    if awk -v port="$port" -v address="$datastore_address" '$4 ~ ":" port "$" && $4 != address ":" port' <<<"$listeners" | grep -q .; then
        die "port $port is bound to another address than $datastore_address"
    fi
done
printf 'ok every datastore port is bound to the lab address only\n'

reaches_out="$(ssh -n "${ssh_options[@]}" "$datastore_user@$datastore_address" "if timeout $CONNECT_TIMEOUT bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then echo yes; else echo no; fi")"
[[ "$reaches_out" == "no" ]] || die "the datastore VM reaches 1.1.1.1"
printf 'ok the datastore VM has no route out\n'
