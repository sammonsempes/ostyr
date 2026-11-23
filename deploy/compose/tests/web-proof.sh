#!/usr/bin/env bash
# Usage: web-proof.sh <analyst-password> <totp-code> <ca-file>   (run in the compose directory inside the lab VM by compose-lab.sh)
# Fetches the sign-in page of the web service over TLS, signs in as the analyst and lists the alerts through the UI. Prints "name value" lines.
set -euo pipefail

readonly ANALYST_PASSWORD="${1:?usage: web-proof.sh <analyst-password> <totp-code> <ca-file>}"
readonly TOTP_CODE="${2:?usage: web-proof.sh <analyst-password> <totp-code> <ca-file>}"
readonly CA_FILE="${3:?usage: web-proof.sh <analyst-password> <totp-code> <ca-file>}"
readonly BASE=https://localhost:9443
readonly PLAIN_TIMEOUT_SECONDS=5
jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT

page="$(curl --silent --fail --cacert "$CA_FILE" --cookie-jar "$jar" "$BASE/login")"
csrf="$(printf '%s' "$page" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p')"
printf 'login_page %s\n' "$(printf '%s' "$page" | grep -c 'action="/login"')"
status="$(curl --silent --output /dev/null --write-out '%{http_code}' --cacert "$CA_FILE" --cookie "$jar" --cookie-jar "$jar" \
    --data-urlencode "csrf=$csrf" --data-urlencode username=analyst --data-urlencode "password=$ANALYST_PASSWORD" \
    --data-urlencode "totp_code=$TOTP_CODE" "$BASE/login")"
printf 'login_status %s\n' "$status"
printf 'alerts_status %s\n' "$(curl --silent --output /dev/null --write-out '%{http_code}' --cacert "$CA_FILE" --cookie "$jar" "$BASE/alerts")"
printf 'plain_http_status %s\n' "$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time "$PLAIN_TIMEOUT_SECONDS" http://localhost:9443/login || true)"
