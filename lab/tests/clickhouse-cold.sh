#!/usr/bin/env bash
# Usage: lab/tests/clickhouse-cold.sh <task-id>
# On a booted datastore-pair lab: adds to the datastore VM's ClickHouse an s3 disk on the Garage endpoint (TLS, lab CA) and a hot_cold storage policy,
# creates the events table from the siem-schema renderer's DDL (lab/tests/fixtures/events-cold.sql, kept equal to the renderer by a siem-schema test),
# inserts rows older than the TTL move, forces the move to the cold volume, then checks system.parts, the objects in the Garage bucket and that
# count() is unchanged. Prints "ok" per check.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly ROWS=300
readonly AGE_DAYS=3
readonly READY_ATTEMPTS=60
readonly READY_DELAY_SECONDS=2

task_id="${1:?usage: clickhouse-cold.sh <task-id>}"
lab_state="$(state_dir "$task_id")"
fixture="$(dirname "${BASH_SOURCE[0]}")/fixtures/events-cold.sql"
read -r _ datastore_user datastore_address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
[[ -n "$datastore_address" ]] || die "vms.txt lacks the datastore VM"
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
ddl_base64="$(base64 -w0 "$fixture")"

ssh "${ssh_options[@]}" "$datastore_user@$datastore_address" "sudo bash -s '$ddl_base64' '$ROWS' '$AGE_DAYS' '$READY_ATTEMPTS' '$READY_DELAY_SECONDS'" <<'REMOTE'
set -euo pipefail
ddl="$(base64 -d <<<"$1")"
rows="$2"
age_days="$3"
ready_attempts="$4"
ready_delay="$5"
source /etc/ostyr-lab/datastore.env
step() { printf 'ok %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1" >&2; exit 1; }

clickhouse() {
    curl --fail --silent --show-error --cacert "$DATASTORE_CA" --user "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" --data-binary "$1" \
        "https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT/"
}
s3_list() {
    curl --fail --silent --show-error --cacert "$DATASTORE_CA" --user "$(cat "$S3_ACCESS_FILE"):$(cat "$S3_SECRET_FILE")" \
        --aws-sigv4 "aws:amz:$S3_REGION:s3" "$S3_ENDPOINT/$S3_BUCKET/?list-type=2&prefix=clickhouse-cold/"
}

cat >/etc/clickhouse-server/config.d/ostyr-cold.xml <<XML
<clickhouse>
    <openSSL>
        <client>
            <caConfig>$DATASTORE_CA</caConfig>
            <loadDefaultCAFile>true</loadDefaultCAFile>
            <verificationMode>relaxed</verificationMode>
            <invalidCertificateHandler><name>RejectCertificateHandler</name></invalidCertificateHandler>
        </client>
    </openSSL>
    <storage_configuration>
        <disks>
            <cold_s3>
                <type>s3</type>
                <endpoint>$S3_ENDPOINT/$S3_BUCKET/clickhouse-cold/</endpoint>
                <access_key_id>$(cat "$S3_ACCESS_FILE")</access_key_id>
                <secret_access_key>$(cat "$S3_SECRET_FILE")</secret_access_key>
                <region>$S3_REGION</region>
                <metadata_path>/var/lib/clickhouse/disks/cold_s3/</metadata_path>
            </cold_s3>
        </disks>
        <policies>
            <hot_cold>
                <volumes>
                    <hot><disk>default</disk></hot>
                    <cold><disk>cold_s3</disk></cold>
                </volumes>
            </hot_cold>
        </policies>
    </storage_configuration>
</clickhouse>
XML
chown clickhouse:clickhouse /etc/clickhouse-server/config.d/ostyr-cold.xml
chmod 640 /etc/clickhouse-server/config.d/ostyr-cold.xml
systemctl restart clickhouse-server
ready=0
for ((attempt = 0; attempt < ready_attempts && ready == 0; attempt++)); do
    if [[ "$(clickhouse 'SELECT 1' 2>/dev/null || true)" == "1" ]]; then ready=1; else sleep "$ready_delay"; fi
done
[[ "$ready" == 1 ]] || fail "ClickHouse did not come back after the storage configuration"
[[ "$(clickhouse "SELECT count() FROM system.storage_policies WHERE policy_name = 'hot_cold' AND volume_name = 'cold' AND disks = ['cold_s3']")" == "1" ]] ||
    fail "storage policy hot_cold with the s3 disk is not loaded"
step "s3 disk on the Garage endpoint and storage policy hot_cold loaded"

clickhouse 'DROP TABLE IF EXISTS default.events_cold SYNC' >/dev/null
clickhouse "$ddl" >/dev/null
[[ "$(clickhouse "SELECT engine_full LIKE '%TO VOLUME ''cold''%' AND engine_full LIKE '%tenant_tier%' FROM system.tables WHERE name = 'events_cold'")" == "1" ]] ||
    fail "the table does not carry the TTL move keyed on tenant_tier"
step "events table created from the renderer DDL with TTL TO VOLUME 'cold'"

clickhouse "INSERT INTO default.events_cold (\`@timestamp\`, tenant, tenant_tier, \`event.id\`, message) SELECT now(), 'lab', 'standard', toString(number), 'cold check' FROM numbers($rows)" >/dev/null
before="$(clickhouse 'SELECT count() FROM default.events_cold')"
[[ "$before" == "$rows" ]] || fail "expected $rows rows before the move, got $before"
[[ "$(clickhouse "SELECT DISTINCT disk_name FROM system.parts WHERE table = 'events_cold' AND active")" == "default" ]] || fail "parts are not on the hot disk before the move"
step "$rows fresh rows inserted on the hot disk"

partition="$(clickhouse "SELECT DISTINCT partition FROM system.parts WHERE table = 'events_cold' AND active" | head -n 1)"
clickhouse "ALTER TABLE default.events_cold MOVE PARTITION '$partition' TO VOLUME 'cold'" >/dev/null
[[ "$(clickhouse "SELECT DISTINCT disk_name FROM system.parts WHERE table = 'events_cold' AND active")" == "cold_s3" ]] || fail "parts are not on cold_s3 after the move"
step "system.parts shows disk_name cold_s3 after MOVE PARTITION"

objects="$(s3_list | grep -o '<Key>' | wc -l)"
[[ "$objects" -gt 0 ]] || fail "no object in the Garage bucket under clickhouse-cold/"
step "$objects objects present in the Garage bucket"

after="$(clickhouse 'SELECT count() FROM default.events_cold')"
[[ "$after" == "$before" ]] || fail "count() changed from $before to $after"
[[ "$(clickhouse "SELECT count() FROM default.events_cold WHERE \`event.id\` = '7'")" == "1" ]] || fail "a row is not readable from the cold disk"
step "count() equal before and after ($after) and rows read back from S3"

clickhouse "INSERT INTO default.events_cold (\`@timestamp\`, tenant, tenant_tier, \`event.id\`, message) SELECT now() - INTERVAL $age_days DAY, 'lab', 'standard', toString(number), 'old' FROM numbers($rows)" >/dev/null
moved=0
for ((attempt = 0; attempt < ready_attempts && moved == 0; attempt++)); do
    if [[ "$(clickhouse "SELECT count() FROM system.parts WHERE table = 'events_cold' AND active AND disk_name = 'default'")" == "0" ]]; then
        moved=1
    else
        sleep "$ready_delay"
    fi
done
[[ "$moved" == 1 ]] || fail "the TTL did not move the old rows to the cold volume"
[[ "$(clickhouse 'SELECT count() FROM default.events_cold')" == "$((rows * 2))" ]] || fail "count() wrong after the TTL move"
step "the TTL itself moved rows older than the move delay to cold_s3, count() intact"
REMOTE
