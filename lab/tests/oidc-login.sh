#!/usr/bin/env bash
# Usage: lab/tests/oidc-login.sh <task-id> [mapped|unmapped]
# Drives the authorization code flow (PKCE S256) against the Zitadel hosted login of a booted oidc-pair lab with curl, from the host.
# Prints "code=<code>", "state=<state>", "code_verifier=<verifier>" and "redirect=<final redirect url>" on stdout.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly IDP_DOMAIN="zitadel.lab.test"
readonly MAX_STEPS=12
readonly VERIFIER_BYTES=32

task_id="${1:?usage: oidc-login.sh <task-id> [mapped|unmapped]}"
user_kind="${2:-mapped}"
[[ "$user_kind" =~ ^(mapped|unmapped)$ ]] || die "user must be mapped or unmapped"
lab_state="$(state_dir "$task_id")"
read -r _ idp_user idp_address < <(awk '$1 == "zitadel"' "$lab_state/vms.txt")
[[ -n "$idp_address" ]] || die "no zitadel VM in $lab_state/vms.txt"

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
ssh -n -i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    "$idp_user@$idp_address" "sudo cat /etc/ostyr-lab/oidc.env /etc/ostyr-lab/ca.pem" >"$work_dir/combined"
sed -n '/^OIDC_/p' "$work_dir/combined" >"$work_dir/oidc.env"
sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$work_dir/combined" >"$work_dir/ca.pem"
set -a
source "$work_dir/oidc.env"
set +a
login_var="OIDC_${user_kind^^}_LOGIN"
password_var="OIDC_${user_kind^^}_PASSWORD"
login_name="${!login_var}"
password="${!password_var}"

verifier="$(openssl rand -hex "$VERIFIER_BYTES")"
challenge="$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')"
state="$(openssl rand -hex "$VERIFIER_BYTES")"

fetch() {
    curl --silent --show-error --cacert "$work_dir/ca.pem" --resolve "$IDP_DOMAIN:443:$idp_address" --cookie "$work_dir/jar" --cookie-jar "$work_dir/jar" \
        --dump-header "$work_dir/headers" --output "$work_dir/body" "$@"
}

location() {
    tr -d '\r' <"$work_dir/headers" | sed -n 's/^[Ll]ocation: //p' | tail -n 1
}

absolute() {
    case "$1" in
        http*) printf '%s' "$1" ;;
        *) printf 'https://%s%s' "$IDP_DOMAIN" "$1" ;;
    esac
}

form_value() {
    sed -n "s/.*name=\"$1\"[^>]*value=\"\([^\"]*\)\".*/\1/p" "$work_dir/body" | head -n 1
}

auth_url="$(jq -rn --arg issuer "$OIDC_ISSUER" --arg client "$OIDC_CLIENT_ID" --arg redirect "$OIDC_REDIRECT_URI" --arg state "$state" \
    --arg challenge "$challenge" '$issuer + "/oauth/v2/authorize?response_type=code&code_challenge_method=S256&scope=" +
    ("openid profile email urn:zitadel:iam:org:project:roles" | @uri) + "&client_id=" + $client + "&redirect_uri=" + ($redirect | @uri) +
    "&state=" + $state + "&code_challenge=" + $challenge')"

follow_to_login() {
    local url="$1" step next
    for ((step = 0; step < MAX_STEPS; step++)); do
        fetch "$url"
        next="$(location)"
        if [[ -z "$next" ]]; then
            return 0
        fi
        url="$(absolute "$next")"
    done
    die "too many redirects before the login form"
}
follow_to_login "$auth_url"
request_id="$(form_value authRequestID)"
csrf="$(form_value gorilla.csrf.Token)"
[[ -n "$request_id" && -n "$csrf" ]] || die "login form not found: $(head -c 300 "$work_dir/body")"

fetch --data-urlencode "authRequestID=$request_id" --data-urlencode "loginName=$login_name" --data-urlencode "gorilla.csrf.Token=$csrf" \
    "https://$IDP_DOMAIN/ui/login/loginname"
csrf="$(form_value gorilla.csrf.Token)"
fetch --data-urlencode "authRequestID=$request_id" --data-urlencode "password=$password" --data-urlencode "gorilla.csrf.Token=$csrf" \
    "https://$IDP_DOMAIN/ui/login/password"

final=""
url="$(absolute "$(location)")"
for ((step = 0; step < MAX_STEPS; step++)); do
    if [[ "$url" == "$OIDC_REDIRECT_URI"* ]]; then
        final="$url"
        break
    fi
    fetch "$url"
    next="$(location)"
    [[ -n "$next" ]] || die "no redirect to $OIDC_REDIRECT_URI, stuck at $url: $(head -c 300 "$work_dir/body")"
    url="$(absolute "$next")"
done
[[ -n "$final" ]] || die "no redirect to $OIDC_REDIRECT_URI"

code="$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<<"$final")"
returned_state="$(sed -n 's/.*[?&]state=\([^&]*\).*/\1/p' <<<"$final")"
[[ -n "$code" && "$returned_state" == "$state" ]] || die "redirect without a code or with a wrong state: $final"
printf 'code=%s\nstate=%s\ncode_verifier=%s\nredirect=%s\n' "$code" "$returned_state" "$verifier" "$final"
