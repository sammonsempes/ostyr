#!/usr/bin/env bash
# Usage: sudo deploy/compose/init.sh <public-host-name>
# Creates deploy/compose/secrets/ once: a throwaway CA (its key is deleted after signing), the PostgreSQL and API certificates, the PostgreSQL
# superuser and service passwords and the account store key. A file that exists is never touched, so a rerun changes nothing. Runs as root: the files the platform
# container reads are handed to uid 65532, the owner the service demands of a secret.
set -euo pipefail

COMPOSE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly COMPOSE_DIR
readonly SECRETS_DIR="$COMPOSE_DIR/secrets"
readonly SERVICE_UID=65532
readonly CERT_DAYS=825
readonly KEY_BYTES=32
readonly NAME_PATTERN='^[A-Za-z0-9.][A-Za-z0-9.-]*$'
readonly ADDRESS_PATTERN='^[0-9]+(\.[0-9]+){3}$'
readonly CURVE=prime256v1

host_name="${1:?usage: init.sh <public-host-name>}"
readonly host_name
if [[ ! "$host_name" =~ $NAME_PATTERN ]]; then
    printf 'error: the host name must match [A-Za-z0-9.-] and not start with a dash\n' >&2
    exit 1
fi
if [[ "$(id -u)" -ne 0 ]]; then
    printf 'error: run as root (the platform secrets must be owned by uid %s)\n' "$SERVICE_UID" >&2
    exit 1
fi

umask 077
mkdir -p "$SECRETS_DIR"
chmod 0700 "$SECRETS_DIR"

make_random_file() {
    local path="$1" encoding="$2" owner="$3"
    if [[ ! -e "$path" ]]; then
        if [[ "$encoding" == base64 ]]; then
            head -c "$KEY_BYTES" /dev/urandom | base64 -w 0 >"$path"
        else
            head -c "$KEY_BYTES" /dev/urandom >"$path"
        fi
        chown "$owner" "$path"
        chmod 0600 "$path"
    fi
}

make_leaf() {
    local name="$1" common_name="$2" alt_names="$3" scratch="$4"
    printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n' "$alt_names" >"$scratch/$name.ext"
    openssl req -newkey ec -pkeyopt "ec_paramgen_curve:$CURVE" -nodes -subj "/CN=$common_name" -keyout "$scratch/$name.key" -out "$scratch/$name.csr"
    openssl x509 -req -in "$scratch/$name.csr" -CA "$scratch/ca.crt" -CAkey "$scratch/ca.key" -CAserial "$scratch/ca.srl" -CAcreateserial \
        -days "$CERT_DAYS" -extfile "$scratch/$name.ext" -out "$scratch/$name.crt"
}

install_new() {
    local source="$1" name="$2" mode="$3" owner="$4"
    if [[ ! -e "$SECRETS_DIR/$name" ]]; then
        install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$source" "$SECRETS_DIR/$name"
    fi
}

make_certificates() {
    local api_names
    if [[ "$host_name" =~ $ADDRESS_PATTERN ]]; then
        api_names="IP:$host_name,DNS:localhost,IP:127.0.0.1"
    else
        api_names="DNS:$host_name,DNS:localhost,IP:127.0.0.1"
    fi
    openssl req -x509 -newkey ec -pkeyopt "ec_paramgen_curve:$CURVE" -nodes -days "$CERT_DAYS" -subj "/CN=Ostyr compose CA" \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout "$scratch/ca.key" -out "$scratch/ca.crt"
    make_leaf pg_server postgres DNS:postgres "$scratch"
    make_leaf api_tls "$host_name" "$api_names" "$scratch"
    install_new "$scratch/ca.crt" ca.crt 0644 root:root
    install_new "$scratch/pg_server.key" pg_server.key 0600 root:root
    install_new "$scratch/pg_server.crt" pg_server.crt 0644 root:root
    install_new "$scratch/api_tls.key" api_tls.key 0600 "$SERVICE_UID:$SERVICE_UID"
    install_new "$scratch/api_tls.crt" api_tls.crt 0644 root:root
}

scratch="$(mktemp -d "$SECRETS_DIR/.tls.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
make_random_file "$SECRETS_DIR/pg_password" base64 root:root
make_random_file "$SECRETS_DIR/pg_service_password" base64 "$SERVICE_UID:$SERVICE_UID"
make_random_file "$SECRETS_DIR/store.key" raw "$SERVICE_UID:$SERVICE_UID"
if [[ ! -e "$SECRETS_DIR/api_tls.crt" ]]; then
    make_certificates
fi
printf 'secrets ready in %s\n' "$SECRETS_DIR"
