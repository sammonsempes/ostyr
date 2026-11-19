#!/usr/bin/env bash
# Usage: sudo deploy/compose/init.sh <public-host-name>
# Creates deploy/compose/secrets/ once: a throwaway CA (its key is deleted after signing), the PostgreSQL and API certificates, the PostgreSQL
# superuser and service passwords and the account store key. A file that exists is never touched, so a rerun changes nothing. Runs as root: the files the platform
# container reads are handed to uid 65532, the owner the service demands of a secret.
set -euo pipefail
export LC_ALL=C
ulimit -c 0

COMPOSE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly COMPOSE_DIR
readonly SECRETS_DIR="$COMPOSE_DIR/secrets"
readonly SERVICE_UID=65532
readonly CERT_DAYS=825
readonly KEY_BYTES=32
readonly ALNUM='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
readonly LABEL_PATTERN="[$ALNUM]([$ALNUM-]{0,61}[$ALNUM])?"
readonly NAME_PATTERN="^${LABEL_PATTERN}(\\.${LABEL_PATTERN})*\$"
readonly NAME_MAX=253
readonly TLS_FILES=(ca.crt pg_server.key pg_server.crt api_tls.key api_tls.crt)
readonly ADDRESS_PATTERN='^[0123456789]+(\.[0123456789]+){3}$'
readonly OCTET_PATTERN='^(25[012345]|2[01234][0123456789]|1[0123456789][0123456789]|[123456789]?[0123456789])$'
readonly PLATFORM_CN=ostyr-platform
readonly CURVE=prime256v1

host_name="${1:?usage: init.sh <public-host-name>}"
readonly host_name
if [[ "${#host_name}" -gt "$NAME_MAX" || ! "$host_name" =~ $NAME_PATTERN ]]; then
    printf 'error: the host name must be DNS labels of 1 to 63 letters, digits or inner dashes, 253 characters at most\n' >&2
    exit 1
fi
if [[ "$host_name" =~ $ADDRESS_PATTERN ]]; then
    IFS=. read -r -a octets <<<"$host_name"
    for octet in "${octets[@]}"; do
        if [[ ! "$octet" =~ $OCTET_PATTERN ]]; then
            printf 'error: %s is not an IPv4 address (each octet is 0 to 255, no leading zero)\n' "$host_name" >&2
            exit 1
        fi
    done
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

stage_file() {
    local name="$1" mode="$2" owner="$3"
    chown "${owner%%:*}:${owner##*:}" "$scratch/$name"
    chmod "$mode" "$scratch/$name"
}

publish_set() {
    trap '' INT TERM HUP QUIT
    local name
    for name in "${TLS_FILES[@]}"; do
        mv -n "$scratch/$name" "$SECRETS_DIR/$name"
    done
    trap 'rm -rf "$scratch"; exit 1' INT TERM HUP QUIT
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
    make_leaf api_tls "$PLATFORM_CN" "$api_names" "$scratch"
    verify_scratch
    stage_file ca.crt 0644 root:root
    stage_file pg_server.key 0600 root:root
    stage_file pg_server.crt 0644 root:root
    stage_file api_tls.key 0600 "$SERVICE_UID:$SERVICE_UID"
    stage_file api_tls.crt 0644 root:root
    publish_set
}

verify_scratch() {
    openssl verify -CAfile "$scratch/ca.crt" "$scratch/pg_server.crt" "$scratch/api_tls.crt" >/dev/null
}

missing_tls_files() {
    local name
    for name in "${TLS_FILES[@]}"; do
        if [[ ! -e "$SECRETS_DIR/$name" ]]; then
            printf '%s\n' "$name"
        fi
    done
}

rm -rf "$SECRETS_DIR"/.tls.*
scratch="$(mktemp -d "$SECRETS_DIR/.tls.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
trap 'rm -rf "$scratch"; exit 1' INT TERM HUP QUIT
missing="$(missing_tls_files | tr '\n' ' ')"
if [[ -n "$missing" ]]; then
    if [[ "$missing" == "${TLS_FILES[*]} " ]]; then
        make_certificates
    else
        printf 'error: the TLS set is incomplete, missing: %s\n' "$missing" >&2
        printf 'remove every TLS file (ca.crt pg_server.* api_tls.*) from %s to regenerate the set\n' "$SECRETS_DIR" >&2
        exit 1
    fi
fi
make_random_file "$SECRETS_DIR/pg_password" base64 root:root
make_random_file "$SECRETS_DIR/pg_service_password" base64 "$SERVICE_UID:$SERVICE_UID"
make_random_file "$SECRETS_DIR/store.key" raw "$SERVICE_UID:$SERVICE_UID"
printf 'secrets ready in %s\n' "$SECRETS_DIR"
