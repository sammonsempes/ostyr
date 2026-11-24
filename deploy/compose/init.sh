#!/usr/bin/env bash
# Usage: sudo deploy/compose/init.sh <public-host-name>
# Creates deploy/compose/secrets/ once: a throwaway CA (its key is deleted after signing), the PostgreSQL and API certificates, the PostgreSQL
# superuser and service passwords and the account store key. A file that exists is never touched, so a rerun changes nothing. Runs as root: the files the platform
# container reads are handed to uid 65532, the owner the service demands of a secret.
set -euo pipefail
export LC_ALL=C
ulimit -c 0

COMPOSE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly COMPOSE_DIR
readonly SECRETS_DIR="$COMPOSE_DIR/secrets"
readonly SERVICE_UID=65532
readonly PLAYBOOKS_UID=65533
readonly CERT_DAYS=825
readonly KEY_BYTES=32
readonly ALNUM='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
readonly LABEL_PATTERN="[$ALNUM]([$ALNUM-]{0,61}[$ALNUM])?"
readonly NAME_PATTERN="^${LABEL_PATTERN}(\\.${LABEL_PATTERN})*\$"
readonly NAME_MAX=253
readonly TLS_FILES=(ca.crt pg_server.key pg_server.crt api_tls.key api_tls.crt)
readonly ADDRESS_PATTERN='^[0123456789]+(\.[0123456789]+){3}$'
readonly OCTET_PATTERN='^(25[012345]|2[01234][0123456789]|1[0123456789][0123456789]|[123456789]?[0123456789])$'
readonly HEX_LABEL_PATTERN='^0[xX][0123456789abcdefABCDEF]+$'
readonly DIGITS_PATTERN='^[0123456789]+$'
readonly BASE64_LENGTH=44
readonly PLATFORM_CN=ostyr-platform
readonly CURVE=prime256v1
readonly LOCK_FILE="$SECRETS_DIR/.lock"
readonly LOCK_WAIT_DEFAULT=30
readonly LOCK_WAIT_SECONDS="${INIT_LOCK_WAIT_SECONDS:-$LOCK_WAIT_DEFAULT}"
readonly LOCK_FD=9
readonly UNSAFE_MODE_BITS=022
readonly PRIVATE_MODE_BITS=077
readonly STICKY_BIT=1000
readonly NON_PRINTABLE_PATTERN='[^[:print:]]'

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
if [[ ! "$host_name" =~ $ADDRESS_PATTERN ]]; then
    IFS=. read -r -a labels <<<"$host_name"
    for label in "${labels[@]}"; do
        if [[ "$label" =~ $HEX_LABEL_PATTERN ]]; then
            printf 'error: the label %s reads as a hexadecimal IPv4 part, refused\n' "$label" >&2
            exit 1
        fi
    done
    if [[ "${labels[-1]}" =~ $DIGITS_PATTERN ]]; then
        printf 'error: a name whose last label is all digits must be a dotted-quad IPv4 address, refused\n' >&2
        exit 1
    fi
fi
if [[ "$(id -u)" -ne 0 ]]; then
    printf 'error: run as root (the platform secrets must be owned by uid %s)\n' "$SERVICE_UID" >&2
    exit 1
fi

if [[ ! "$LOCK_WAIT_SECONDS" =~ $DIGITS_PATTERN ]]; then
    printf 'error: INIT_LOCK_WAIT_SECONDS must be a whole number of seconds\n' >&2
    exit 1
fi

check_ancestor() {
    local component="$1" mode
    mode="$(stat -c %a "$component")"
    if [[ "$(stat -c %u "$component")" != 0 ]]; then
        printf 'error: %s must be owned by root\n' "$component" >&2
        exit 1
    fi
    if [[ $((8#$mode & 8#$UNSAFE_MODE_BITS)) -ne 0 ]]; then
        if [[ "$component" == "$COMPOSE_DIR" || $((8#$mode & 8#$STICKY_BIT)) -eq 0 ]]; then
            printf 'error: %s must not be writable by group or others\n' "$component" >&2
            exit 1
        fi
    fi
}

check_ancestors() {
    local component="" part
    local -a parts
    if [[ "$COMPOSE_DIR" =~ $NON_PRINTABLE_PATTERN ]]; then
        printf 'error: the directory of init.sh must hold printable ASCII only (no control character, newline or non-ASCII byte)\n' >&2
        exit 1
    fi
    check_ancestor /
    readarray -d / -t parts < <(printf '%s' "${COMPOSE_DIR#/}")
    for part in "${parts[@]}"; do
        component="$component/$part"
        check_ancestor "$component"
    done
}

umask 077
check_ancestors
mkdir -p "$SECRETS_DIR"
if [[ -L "$SECRETS_DIR" || ! -d "$SECRETS_DIR" || "$(stat -c %u "$SECRETS_DIR")" != 0 ]]; then
    printf 'error: %s must be a directory owned by root, not a symlink\n' "$SECRETS_DIR" >&2
    exit 1
fi
if [[ $((8#$(stat -c %a "$SECRETS_DIR") & 8#$PRIVATE_MODE_BITS)) -ne 0 ]]; then
    printf 'error: %s must have no group or other permission bits (chmod 0700 it, check what is inside)\n' "$SECRETS_DIR" >&2
    exit 1
fi
if [[ -e "$LOCK_FILE" || -L "$LOCK_FILE" ]]; then
    if [[ -L "$LOCK_FILE" || ! -f "$LOCK_FILE" || "$(stat -c %u "$LOCK_FILE")" != 0 ]]; then
        printf 'error: %s must be a regular file owned by root, not a link\n' "$LOCK_FILE" >&2
        exit 1
    fi
fi
exec 9>>"$LOCK_FILE"
if ! flock -w "$LOCK_WAIT_SECONDS" "$LOCK_FD"; then
    printf 'error: another init.sh holds the lock on %s, wait for it and rerun\n' "$SECRETS_DIR" >&2
    exit 1
fi

is_present() {
    [[ -e "$1" || -L "$1" ]]
}

expected_owner() {
    case "$1" in
    api_tls.key | pg_service_password | store.key) printf '%s:%s' "$SERVICE_UID" "$SERVICE_UID" ;;
    playbooks_pg_password) printf '%s:%s' "$PLAYBOOKS_UID" "$PLAYBOOKS_UID" ;;
    *) printf '0:0' ;;
    esac
}

expected_mode() {
    case "$1" in
    *.crt) printf '644' ;;
    playbooks_pg_password) printf '400' ;;
    *) printf '600' ;;
    esac
}

check_present() {
    local name="$1" size="${2:-}" path="$SECRETS_DIR/$1"
    if [[ -L "$path" || ! -f "$path" || "$(stat -c %u:%g "$path")" != "$(expected_owner "$name")" ]]; then
        printf 'error: %s must be a regular file owned by %s, remove it and rerun\n' "$path" "$(expected_owner "$name")" >&2
        exit 1
    fi
    if [[ "$(stat -c %a "$path")" != "$(expected_mode "$name")" ]]; then
        printf 'error: %s must have mode %s, remove it and rerun\n' "$path" "$(expected_mode "$name")" >&2
        exit 1
    fi
    if [[ -n "$size" && "$(stat -c %s "$path")" != "$size" ]]; then
        printf 'error: %s is not %s bytes long, remove it and rerun\n' "$path" "$size" >&2
        exit 1
    fi
    if [[ "$(stat -c %h "$path")" != 1 ]]; then
        printf 'error: %s has more than one hard link, remove it and rerun\n' "$path" >&2
        exit 1
    fi
}

make_random_file() {
    local name="$1" encoding="$2" size="$KEY_BYTES" temporary
    if [[ "$encoding" == base64 ]]; then
        size="$BASE64_LENGTH"
    fi
    if is_present "$SECRETS_DIR/$name"; then
        check_present "$name" "$size"
    else
        temporary="$(mktemp "$scratch/$name.XXXXXX")"
        if [[ "$encoding" == base64 ]]; then
            head -c "$KEY_BYTES" /dev/urandom | base64 -w 0 >"$temporary"
        else
            head -c "$KEY_BYTES" /dev/urandom >"$temporary"
        fi
        chown -h "$(expected_owner "$name")" "$temporary"
        chmod 0600 "$temporary"
        ln "$temporary" "$SECRETS_DIR/$name"
    fi
}

make_copy_file() {
    local name="$1" source="$2" temporary
    if is_present "$SECRETS_DIR/$name"; then
        check_present "$name" "$BASE64_LENGTH"
    else
        temporary="$(mktemp "$scratch/$name.XXXXXX")"
        cat "$SECRETS_DIR/$source" >"$temporary"
        chown -h "$(expected_owner "$name")" "$temporary"
        chmod 0400 "$temporary"
        ln "$temporary" "$SECRETS_DIR/$name"
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
    local name="$1" mode="$2" owner="$3" staged_fd
    if [[ -L "$scratch/$name" ]]; then
        printf 'error: %s is a symlink, refused\n' "$scratch/$name" >&2
        exit 1
    fi
    exec {staged_fd}<"$scratch/$name"
    if [[ -L "$scratch/$name" || "$(stat -c %d:%i "$scratch/$name")" != "$(stat -L -c %d:%i "/proc/self/fd/$staged_fd")" ]]; then
        printf 'error: %s changed while it was staged, refused\n' "$scratch/$name" >&2
        exit 1
    fi
    chown "${owner%%:*}:${owner##*:}" "/proc/self/fd/$staged_fd"
    chmod "$mode" "/proc/self/fd/$staged_fd"
    staged_inode[$name]="$(stat -L -c %d:%i "/proc/self/fd/$staged_fd")"
    staged_descriptors+=("$staged_fd")
}

close_staged() {
    local descriptor
    for descriptor in "${staged_descriptors[@]}"; do
        exec {descriptor}<&-
    done
    staged_descriptors=()
}

link_set() {
    local name
    for name in "${TLS_FILES[@]}"; do
        if [[ -L "$scratch/$name" || "$(stat -c %d:%i "$scratch/$name")" != "${staged_inode[$name]}" ]]; then
            return 1
        fi
        ln "$scratch/$name" "$SECRETS_DIR/$name" || return 1
        linked_names+=("$name")
    done
}

unlink_published() {
    local name
    for name in "${linked_names[@]}"; do
        if [[ ! -L "$SECRETS_DIR/$name" && "$(stat -c %d:%i "$SECRETS_DIR/$name")" == "${staged_inode[$name]}" ]]; then
            rm -f "$SECRETS_DIR/$name"
        fi
    done
}

publish_set() {
    trap '' INT TERM HUP QUIT
    if ! link_set; then
        unlink_published
        printf 'error: a name appeared in %s during the publish, this run removed what it had published\n' "$SECRETS_DIR" >&2
        exit 1
    fi
    close_staged
    trap 'rm -rf "$scratch"; exit 1' INT TERM HUP QUIT
}

make_certificates() {
    local api_names
    if [[ "$host_name" =~ $ADDRESS_PATTERN ]]; then
        api_names="IP:$host_name,DNS:platform,DNS:localhost,IP:127.0.0.1"
    else
        api_names="DNS:$host_name,DNS:platform,DNS:localhost,IP:127.0.0.1"
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
        if ! is_present "$SECRETS_DIR/$name"; then
            printf '%s\n' "$name"
        fi
    done
}

declare -A staged_inode=()
linked_names=()
staged_descriptors=()
rm -rf "$SECRETS_DIR"/.tls.*
scratch=""
trap 'rm -rf "$scratch"' EXIT
trap 'rm -rf "$scratch"; exit 1' INT TERM HUP QUIT
scratch="$(mktemp -d "$SECRETS_DIR/.tls.XXXXXX")"
missing="$(missing_tls_files | tr '\n' ' ')"
if [[ -n "$missing" ]]; then
    if [[ "$missing" == "${TLS_FILES[*]} " ]]; then
        make_certificates
    else
        printf 'error: the TLS set is incomplete, missing: %s\n' "$missing" >&2
        printf 'remove every TLS file (ca.crt pg_server.* api_tls.*) from %s to regenerate the set\n' "$SECRETS_DIR" >&2
        exit 1
    fi
else
    for tls_name in "${TLS_FILES[@]}"; do
        check_present "$tls_name"
    done
fi
if ! openssl x509 -in "$SECRETS_DIR/api_tls.crt" -noout -ext subjectAltName | grep -Eq 'DNS:platform(,|$)'; then
    printf 'warning: api_tls.crt has no DNS:platform name, so the web service cannot verify the API\n' >&2
    printf 'to fix it, remove every TLS file (ca.crt pg_server.* api_tls.*) from %s and rerun init.sh; nothing was changed\n' "$SECRETS_DIR" >&2
fi
make_random_file pg_password base64
make_random_file pg_service_password base64
make_random_file store.key raw
make_copy_file playbooks_pg_password pg_service_password
printf 'secrets ready in %s\n' "$SECRETS_DIR"
