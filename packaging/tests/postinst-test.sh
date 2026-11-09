#!/usr/bin/env bash
# Usage: packaging/tests/postinst-test.sh
# Runs the maintainer scripts in a scratch tree (OSTYR_ROOT) with stubbed adduser, deluser and chown: state directory 0700, key and certificate modes,
# idempotence (an upgrade keeps the key and the certificate), the service user is created once.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGING_DIR="$(dirname "$TESTS_DIR")"
REPO_DIR="$(dirname "$PACKAGING_DIR")"
readonly TESTS_DIR PACKAGING_DIR REPO_DIR
readonly KEY_BYTES=32

mkdir -p "$REPO_DIR/target"
work="$(mktemp -d "$REPO_DIR/target/packaging-postinst.XXXXXX")"
trap 'rm -rf "$work"' EXIT
failures=0

expect() {
    local description="$1"
    shift
    if "$@"; then
        printf 'ok   %s\n' "$description"
    else
        printf 'FAIL %s\n' "$description"
        failures=$((failures + 1))
    fi
}

mode_of() {
    stat -c '%a' "$1"
}

mkdir -p "$work/bin" "$work/root"
for stub in adduser chown; do
    printf '#!/bin/sh\nprintf "%s %%s\\n" "$*" >>"%s/calls.log"\n' "$stub" "$work" >"$work/bin/$stub"
    chmod +x "$work/bin/$stub"
done
printf '#!/bin/sh\nexit 2\n' >"$work/bin/getent"
chmod +x "$work/bin/getent"

run_postinst() {
    PATH="$work/bin:$PATH" OSTYR_ROOT="$work/root" sh "$PACKAGING_DIR/debian/postinst" configure
}

state="$work/root/var/lib/ostyr-example-module"
config="$work/root/etc/ostyr/example-module"

run_postinst
expect "state directory is 0700" test "$(mode_of "$state")" = 700
expect "store key is 0600" test "$(mode_of "$config/store.key")" = 600
expect "store key is $KEY_BYTES bytes" test "$(stat -c '%s' "$config/store.key")" = "$KEY_BYTES"
expect "TLS key is 0600" test "$(mode_of "$config/tls.key")" = 600
expect "TLS certificate is 0644" test "$(mode_of "$config/tls.crt")" = 644
expect "certificate names localhost" bash -c "openssl x509 -in '$config/tls.crt' -noout -ext subjectAltName | grep -q 'DNS:localhost'"
expect "the certificate verifies against ca.crt" openssl verify -CAfile "$config/ca.crt" "$config/tls.crt"
expect "the CA private key and scratch files are not kept" test -z "$(find "$work/root" -name 'ca.key' -o -name '*.csr' -o -name '*.srl' -o -name '.tls.*')"
expect "ca.crt is 0644" test "$(mode_of "$config/ca.crt")" = 644
expect "certificate and key match" test "$(openssl x509 -in "$config/tls.crt" -noout -pubkey)" = "$(openssl pkey -in "$config/tls.key" -pubout)"
expect "the service user is created as a system user without a shell" grep -q 'adduser --system --group --no-create-home .* /usr/sbin/nologin ostyr-module' "$work/calls.log"
expect "the state directory is handed to the service user" grep -q "chown ostyr-module:ostyr-module $state" "$work/calls.log"
expect "the store key is handed to the service user" grep -q "chown ostyr-module:ostyr-module $config/store.key" "$work/calls.log"

key_before="$(sha256sum "$config/store.key")"
certificate_before="$(sha256sum "$config/tls.crt")"
chmod 0755 "$state"
run_postinst
expect "an upgrade keeps the store key" test "$key_before" = "$(sha256sum "$config/store.key")"
expect "an upgrade keeps the certificate" test "$certificate_before" = "$(sha256sum "$config/tls.crt")"
expect "an upgrade restores the state directory mode" test "$(mode_of "$state")" = 700

printf '#!/bin/sh\nexit 0\n' >"$work/bin/getent"
: >"$work/calls.log"
run_postinst
expect "an existing service user is not created again" bash -c "! grep -q adduser '$work/calls.log'"

expect "other maintainer actions change nothing" bash -c "PATH='$work/bin:$PATH' OSTYR_ROOT='$work/other' sh '$PACKAGING_DIR/debian/postinst' abort-upgrade && test ! -e '$work/other'"

if [[ "$failures" -ne 0 ]]; then
    printf '%s check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'all checks passed\n'
