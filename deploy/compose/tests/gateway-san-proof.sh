#!/usr/bin/env bash
# Usage: sudo gateway-san-proof.sh <copy of the compose directory holding a finished secrets/>
# Plants a gateway_tls.crt with an extra DNS name, then one whose first DNS name holds a newline and the text of the extension header (OpenSSL prints a DNS
# value raw), runs init.sh on each and expects the named warning and every file of secrets/ unchanged. Run it on a copy, never on the real secrets.
set -euo pipefail

copy="${1:?usage: gateway-san-proof.sh <compose directory copy>}"
readonly copy
failures=0

san_extension_der() {
    local body="" name hex
    for name in "$@"; do
        hex="$(printf '%s' "$name" | od -An -tx1 | tr -d ' \n')"
        body+="$(printf '82%02x%s' $((${#hex} / 2)) "$hex")"
    done
    printf '30%02x%s' $((${#body} / 2)) "$body"
}

prove() {
    local description="$1" extension="$2" before after output
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout /dev/null -out "$copy/secrets/gateway_tls.crt" -subj /CN=gateway -addext "subjectAltName=$extension" 2>/dev/null
    chmod 0644 "$copy/secrets/gateway_tls.crt"
    before="$(sha256sum "$copy"/secrets/* | sort)"
    output="$(cd "$copy" && ./init.sh lab.example 2>&1)"
    after="$(sha256sum "$copy"/secrets/* | sort)"
    if grep -q 'gateway_tls.crt names more than DNS:gateway' <<<"$output" && [[ "$before" == "$after" ]]; then
        printf 'ok   %s\n' "$description"
    else
        printf 'FAIL %s\n%s\n' "$description" "$output"
        failures=$((failures + 1))
    fi
}

prove "an extra DNS name in the gateway certificate warns by name and changes no file" DNS:gateway,DNS:platform
prove "a DNS name holding a newline and the extension header warns by name and changes no file" "DER:$(san_extension_der $'gateway\nSubject Alternative Name' platform)"
[[ "$failures" -eq 0 ]]
