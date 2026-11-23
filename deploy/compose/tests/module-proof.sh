#!/usr/bin/env bash
# Usage: module-proof.sh <ca-file> <analyst-token> <auditor-token> <responder-token> <reader-token>   (run in the lab VM by compose-lab.sh)
# The API admits 30 requests per source per minute, so the script pauses a window before it starts and after every 24 requests.
# One line per mounted module: "<module> <OpenAPI template listed 1|0> <no token> <token of the role that owns the route> <reader token>" (HTTP codes).
set -uo pipefail

readonly CA="${1:?usage: module-proof.sh <ca-file> <analyst> <auditor> <responder> <reader>}"
readonly ANALYST="${2:?}"
readonly AUDITOR="${3:?}"
readonly RESPONDER="${4:?}"
readonly READER="${5:?}"
readonly BASE=https://localhost:8443
readonly SAMPLE_START=1700000000
readonly RATE_BUDGET=24
readonly RATE_PAUSE_SECONDS=61
requests=0
NOW="$(date +%s)"
readonly NOW
readonly INCIDENT="{\"service\":\"platform\",\"title\":\"module proof\",\"published\":false,\"started_at\":$NOW}"
OPENAPI_FILE="$(mktemp)"
readonly OPENAPI_FILE

pace() {
    if [[ $((requests + $1)) -gt "$RATE_BUDGET" ]]; then
        sleep "$RATE_PAUSE_SECONDS"
        requests=0
    fi
    requests=$((requests + $1))
}

http_code() {
    local method="$1" path="$2" token="$3"
    local arguments=(--silent --output /dev/null --write-out '%{http_code}' --cacert "$CA" --request "$method")
    [[ -n "$token" ]] && arguments+=(-H "Authorization: Bearer $token")
    [[ "$method" == POST ]] && arguments+=(-H 'Content-Type: application/json' --data "$INCIDENT")
    curl "${arguments[@]}" "$BASE$path"
}

listed() {
    if grep -qF "\"$1\"" "$OPENAPI_FILE"; then echo 1; else echo 0; fi
}

sleep "$RATE_PAUSE_SECONDS"
curl --silent --fail --cacert "$CA" "$BASE/openapi.json" >"$OPENAPI_FILE"

proof() {
    local module="$1" method="$2" template="$3" path="$4" owner="$5"
    pace 3
    printf '%s %s %s %s %s\n' "$module" "$(listed "$template")" "$(http_code "$method" "$path" "")" "$(http_code "$method" "$path" "$owner")" "$(http_code "$method" "$path" "$READER")"
}

proof alerts GET /alerts /alerts "$ANALYST"
proof cases GET /cases /cases "$ANALYST"
proof cmdb GET /assets /assets "$ANALYST"
proof risk GET /risk/entities /risk/entities "$ANALYST"
proof hunts GET /hunts/findings /hunts/findings "$ANALYST"
proof certificates GET /certificates /certificates "$ANALYST"
proof oncall GET /oncall/alerts /oncall/alerts "$ANALYST"
proof dhcp GET /dhcp/leases/at "/dhcp/leases/at?address=10.0.0.1&at=$SAMPLE_START" "$ANALYST"
proof compliance GET /compliance/state /compliance/state "$ANALYST"
proof vulnerabilities GET /vulnerabilities/findings /vulnerabilities/findings "$ANALYST"
proof remote_shell GET /remote-shell/sessions /remote-shell/sessions "$AUDITOR"
proof posture GET '/posture/accounts/{account}/findings' /posture/accounts/lab/findings "$ANALYST"
proof status POST /status/incidents /status/incidents "$RESPONDER"
proof grc GET /grc/reports /grc/reports "$ANALYST"
proof attack_paths GET /attack-paths/reports /attack-paths/reports "$ANALYST"
pace 2
printf 'analyst_on_audit_route %s\n' "$(http_code GET /remote-shell/sessions "$ANALYST")"
printf 'analyst_on_status_write %s\n' "$(http_code POST /status/incidents "$ANALYST")"
