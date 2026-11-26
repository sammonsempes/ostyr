#!/bin/bash
# Run as root on the datastore-pair client VM after live-stat.sh: the findings route as the administrator of each tenant (T908).
# Usage: live-stat-api.sh <bin-dir with hunt_api and ostyr-auth>
set -euo pipefail
BIN=$1
ENV_FILE=/etc/ostyr-lab/datastore.env
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
set -a
. "$ENV_FILE"
set +a
umask 077
printf '%s' "$POSTGRES_PASSWORD" >"$WORK/pg.password"
cat >"$WORK/pg.yaml" <<EOF
host: $DATASTORE_DOMAIN
port: $POSTGRES_PORT
database: $POSTGRES_DATABASE
user: $POSTGRES_USER
password_file: $WORK/pg.password
ca_file: $DATASTORE_CA
EOF
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/tls.key" -out "$WORK/tls.crt" -days 1 -subj /CN=127.0.0.1 -addext 'subjectAltName=IP:127.0.0.1' 2>/dev/null
head -c 32 /dev/urandom >"$WORK/store.key"
printf 'passwordpassword\n' >"$WORK/compromised.txt"
AUTH="$BIN/ostyr-auth $WORK/accounts.json $WORK/auth.log $WORK/store.key $WORK/compromised.txt"
PASSWORD='Lab-Admin-Pass-1'
bootstrap=$($AUTH <<<"bootstrap admin $PASSWORD")
secret=$(awk '$1 == "secret" {print $2}' <<<"$bootstrap")
serve() {
    cat >"$WORK/module.yaml" <<EOF
name: hunts
version: "1"
tenant: $1
listen: "127.0.0.1:7460"
settings:
  tls_certificate: $WORK/tls.crt
  tls_key: $WORK/tls.key
  accounts_store: $WORK/accounts.json
  audit_log: $WORK/audit.log
  key_file: $WORK/store.key
  compromised_list: $WORK/compromised.txt
  pg_settings: $WORK/pg.yaml
EOF
    timeout 20 "$BIN/hunt_api" "$WORK/module.yaml" >"$WORK/api-$1.log" 2>&1 &
    for _ in $(seq 1 40); do curl -sk -o /dev/null https://127.0.0.1:7460/ && break; sleep 0.5; done
    code=$($AUTH <<<"totp $secret")
    TOKEN=$(curl -sk -X POST -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"$PASSWORD\",\"totp_code\":\"$code\"}" \
        https://127.0.0.1:7460/auth/login | sed 's/.*"token":"\([^"]*\)".*/\1/')
    echo "--- GET /hunts/findings as the administrator of $1"
    curl -sk -H "Authorization: Bearer $TOKEN" 'https://127.0.0.1:7460/hunts/findings?limit=50'
    echo
    wait || true
}
serve tisoa
sleep 31
serve tisob
echo "--- no token"
timeout 20 "$BIN/hunt_api" "$WORK/module.yaml" >/dev/null 2>&1 &
for _ in $(seq 1 40); do curl -sk -o /dev/null https://127.0.0.1:7460/ && break; sleep 0.5; done
curl -sk -o /dev/null -w '%{http_code}\n' 'https://127.0.0.1:7460/hunts/findings'
wait || true
