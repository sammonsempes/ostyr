#!/bin/bash
set -euo pipefail
umask 077
readonly SERVER=https://clickhouse:8443/
readonly SCHEMA_FILE=/etc/ostyr-schema/schema.sql
readonly WGET_CONFIG=/tmp/wgetrc
readonly STATEMENT_FILE=/tmp/statement.sql
readonly DATABASE=ostyr
printf 'http_user=schema\nhttp_password=%s\nauth_no_challenge=on\nca_certificate=/run/secrets/pg_ca\n' "$(cat /run/secrets/clickhouse_schema_password)" >"$WGET_CONFIG"
export WGETRC="$WGET_CONFIG"
post() {
    wget --content-on-error --no-verbose --tries=1 --output-document=- --post-file="$STATEMENT_FILE" "$1"
}
printf 'CREATE DATABASE IF NOT EXISTS %s' "$DATABASE" >"$STATEMENT_FILE"
post "$SERVER"
mapfile -t lines <"$SCHEMA_FILE"
statement=""
count=0
for line in "${lines[@]}"; do
    if [[ "$line" == ";" ]]; then
        printf '%s' "$statement" >"$STATEMENT_FILE"
        post "$SERVER?database=$DATABASE"
        count=$((count + 1))
        statement=""
    else
        statement+="$line"$'\n'
    fi
done
printf 'schema applied: %s statements\n' "$count"
