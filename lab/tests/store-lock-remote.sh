#!/usr/bin/env bash
# Usage (on the lab VM): store-lock-remote.sh <directory holding auth_tool, module_api and stored-passkey.json>
# Proves that module_api and auth_tool share the account store without losing updates: a passkey removed, a passkey added and a role
# change made through the file while the API runs all survive API logins.
set -euo pipefail

readonly DIR="${1:?usage: store-lock-remote.sh <directory>}"
readonly PASSWORD="correct-horse-battery-staple"
readonly BOB_PASSWORD="another-long-passphrase"
readonly CREDENTIAL_ID="jgUEVIVzNqfEPqeU9eUwhERykDk05jE43P57f36vpz0"
readonly PORT=8443
readonly API="https://127.0.0.1:$PORT"
readonly STORE="$DIR/accounts.json"
failures=0

check() {
    if [[ "$2" == "$3" ]]; then
        printf 'PASS %s: %s\n' "$1" "$2"
    else
        printf 'FAIL %s: got %s, wanted %s\n' "$1" "$2" "$3"
        failures=$((failures + 1))
    fi
}

cd "$DIR"
umask 077
head -c 32 /dev/urandom >key
printf 'passwordpassword\n' >words
printf 'rp_id: lab.test\nrp_origin: https://lab.test\nrp_name: Ostyr\n' >webauthn.yaml
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.pem -days 1 -subj /CN=localhost -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null
cat >module.yaml <<EOF
name: example
version: "1"
listen: 127.0.0.1:$PORT
settings:
  tls_certificate: $DIR/server.pem
  tls_key: $DIR/server.key
  accounts_store: $STORE
  audit_log: $DIR/api-audit.log
  key_file: $DIR/key
  compromised_list: $DIR/words
EOF

coproc TOOL { "$DIR/auth_tool" "$STORE" "$DIR/tool-audit.log" key words webauthn.yaml; }
ask() {
    printf '%s\n' "$1" >&"${TOOL[1]}"
    IFS= read -r -u "${TOOL[0]}" reply
    printf '%s' "$reply"
}

secret_line="$(ask "bootstrap admin $PASSWORD")"
IFS= read -r -u "${TOOL[0]}" _backup
secret="${secret_line#secret }"
code="$(ask "totp $secret")"
token="$(ask "login admin $PASSWORD 10.0.0.9 $code")"
token="${token#ok }"
check "create bob" "$(ask "create $token bob $BOB_PASSWORD analyst")" "ok"

inject_passkey() {
    flock -x "$STORE.lock" bash -c 'jq --slurpfile credential "$1/stored-passkey.json" ".credentials += \$credential" "$2" >"$2.new" && mv "$2.new" "$2"' _ "$DIR" "$STORE"
}
credential_count() { jq '.credentials | length' "$STORE"; }
bob_roles() { jq -c '[.accounts[] | select(.username == "bob") | .roles | sort] | .[0]' "$STORE"; }
login_bob() {
    curl -sk -o /dev/null -w '%{http_code}' -X POST "$API/auth/login" -H 'content-type: application/json' \
        -d "{\"username\":\"bob\",\"password\":\"$BOB_PASSWORD\"}"
}
login_bob_token() {
    curl -sk -X POST "$API/auth/login" -H 'content-type: application/json' -d "{\"username\":\"bob\",\"password\":\"$BOB_PASSWORD\"}" | jq -r .token
}

inject_passkey
check "passkey registered before the API starts" "$(credential_count)" "1"
"$DIR/module_api" module.yaml >api-out.log 2>&1 &
api_pid=$!
trap 'kill "$api_pid" 2>/dev/null || true' EXIT
until curl -sk "$API/health" >/dev/null; do sleep 0.2; done

check "API login with the passkey stored" "$(login_bob)" "200"
check "passkey kept by an API login" "$(credential_count)" "1"
check "CLI removes the passkey while the API runs" "$(ask "wa-remove $token bob $CREDENTIAL_ID")" "ok"
check "API login after the removal" "$(login_bob)" "200"
check "removed passkey stays removed" "$(credential_count)" "0"
inject_passkey
check "API login after a passkey added through the file" "$(login_bob)" "200"
check "added passkey survives" "$(credential_count)" "1"
bob_token="$(login_bob_token)"
check "CLI demotes bob while the API runs" "$(ask "roles $token bob reader")" "ok"
me_status() { curl -sk -o /dev/null -w '%{http_code}' "$API/auth/me" -H "authorization: Bearer $1"; }
check "demotion ends the API session at the next request" "$(me_status "$bob_token")" "401"
check "API login after the demotion" "$(login_bob)" "200"
check "demotion survives the API login" "$(bob_roles)" '["reader"]'
bob_token="$(login_bob_token)"
check "a new session works after the demotion" "$(me_status "$bob_token")" "200"
check "CLI revokes every session of bob" "$(ask "revoke-all $token bob")" "revoked 0"
check "revoke-all ends the API session" "$(me_status "$bob_token")" "401"
bob_token="$(login_bob_token)"
check "a new session works after revoke-all" "$(me_status "$bob_token")" "200"
store_backup="$(cat "$STORE")"
printf 'not json' >"$STORE"
check "an unreadable store refuses an authenticated request" "$(me_status "$bob_token")" "401"
printf '%s' "$store_backup" >"$STORE"
check "CLI still creates accounts after API writes" "$(ask "create $token carol $BOB_PASSWORD reader")" "ok"
check "accounts after both writers" "$(jq '.accounts | length' "$STORE")" "3"
exit "$failures"
