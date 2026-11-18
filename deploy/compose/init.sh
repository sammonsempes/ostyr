#!/usr/bin/env bash
# Usage: sudo deploy/compose/init.sh <public-host-name>
# Creates deploy/compose/secrets/ once: a throwaway CA (its key is deleted after signing), the PostgreSQL and API certificates, the PostgreSQL
# password and the account store key. A file that exists is never touched, so a rerun changes nothing. Runs as root: the files the platform
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
    local path="$1" encoding="$2"
    if [[ ! -e "$path" ]]; then
        if [[ "$encoding" == base64 ]]; then
            head -c "$KEY_BYTES" /dev/urandom | base64 -w 0 >"$path"
        else
            head -c "$KEY_BYTES" /dev/urandom >"$path"
        fi
        chown "$SERVICE_UID:$SERVICE_UID" "$path"
        chmod 0600 "$path"
    fi
}

make_leaf() {
    local name="$1" common_name="$2" alt_names="$3" scratch="$4"
    printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n' "$alt_names" >"$scratch/$name.ext"
    openssl req -newkey ec -pkeyopt "ec_paramgen_curve:$CURVE" -nodes -subj "/CN=$common_name" -keyout "$SECRETS_DIR/$name.key" -out "$scratch/$name.csr"
    openssl x509 -req -in "$scratch/$name.csr" -CA "$SECRETS_DIR/ca.crt" -CAkey "$scratch/ca.key" -CAserial "$scratch/ca.srl" -CAcreateserial \
        -days "$CERT_DAYS" -extfile "$scratch/$name.ext" -out "$SECRETS_DIR/$name.crt"
    chmod 0600 "$SECRETS_DIR/$name.key"
    chmod 0644 "$SECRETS_DIR/$name.crt"
}

make_certificates() {
    local scratch api_names
    if [[ -e "$SECRETS_DIR/api_tls.crt" ]]; then
        return 0
    fi
    if [[ "$host_name" =~ $ADDRESS_PATTERN ]]; then
        api_names="IP:$host_name,DNS:localhost,IP:127.0.0.1"
    else
        api_names="DNS:$host_name,DNS:localhost,IP:127.0.0.1"
    fi
    scratch="$(mktemp -d "$SECRETS_DIR/.tls.XXXXXX")"
    (
        openssl req -x509 -newkey ec -pkeyopt "ec_paramgen_curve:$CURVE" -nodes -days "$CERT_DAYS" -subj "/CN=Ostyr compose CA" \
            -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout "$scratch/ca.key" -out "$SECRETS_DIR/ca.crt"
        make_leaf pg_server postgres DNS:postgres "$scratch"
        make_leaf api_tls "$host_name" "$api_names" "$scratch"
    ) 2>/dev/null
    rm -rf "$scratch"
    chown "$SERVICE_UID:$SERVICE_UID" "$SECRETS_DIR/api_tls.key"
    chmod 0644 "$SECRETS_DIR/ca.crt"
}

make_random_file "$SECRETS_DIR/pg_password" base64
make_random_file "$SECRETS_DIR/store.key" raw
make_certificates
printf 'secrets ready in %s\n' "$SECRETS_DIR"
