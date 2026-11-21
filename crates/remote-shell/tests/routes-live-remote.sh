#!/usr/bin/env bash
# Runs on the client VM of a datastore-pair lab, driven by routes-live.sh: phases setup | refused | good | attacks, state in $WORK.
set -euo pipefail

phase="${1:?phase}"
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
export PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full PGSSLROOTCERT=/etc/ostyr-lab/ca.pem
sql() { psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" -c "$1"; }
register() { $WORK/rshell_register "$WORK/pg.yaml" "$@"; }
PORT_A=${PORT_BASE}
PORT_B=$((PORT_BASE + 1))
PASSWORD_USER="lab-quartz-harbor-77-ok"
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
token_of() { curl -s -X POST "http://127.0.0.1:$1/auth/login" -H 'content-type: application/json' -d "{\"username\":\"$2\",\"password\":\"$PASSWORD_USER\"}" | jq -r '.token // empty'; }
status() { curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $3" "http://127.0.0.1:$1$2"; }
body() { curl -s -H "authorization: Bearer $3" "http://127.0.0.1:$1$2"; }
anonymous_status() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1$2"; }

case "$phase" in
setup)
    mkdir -p "$WORK"
    printf '%s' "$POSTGRES_PASSWORD" >"$WORK/password"
    chmod 600 "$WORK/password"
    cat >"$WORK/pg.yaml" <<YAML
host: $DATASTORE_DOMAIN
port: $POSTGRES_PORT
database: $DATABASE
user: $POSTGRES_USER
password_file: $WORK/password
ca_file: /etc/ostyr-lab/ca.pem
YAML
    printf 'passwordpassword\n' >"$WORK/compromised.txt"
    head -c 32 /dev/urandom >"$WORK/store.key"
    chmod 600 "$WORK/store.key"
    tool() { $WORK/auth_tool "$WORK/accounts.json" "$WORK/auth-audit.log" "$WORK/store.key" "$WORK/compromised.txt" "$@"; }
    bootstrap_output="$(tool <<<"bootstrap admin $PASSWORD_USER")"
    secret="$(awk '$1 == "secret" {print $2}' <<<"$bootstrap_output")"
    code="$(tool <<<"totp $secret")"
    coproc AUTH { tool; }
    printf 'login admin %s 127.0.0.1 %s\n' "$PASSWORD_USER" "$code" >&"${AUTH[1]}"
    read -r -u "${AUTH[0]}" login_line
    admin_token="${login_line##* }"
    printf 'create %s auditor %s auditor\n' "$admin_token" "$PASSWORD_USER" >&"${AUTH[1]}"
    read -r -u "${AUTH[0]}" create_line
    printf 'create %s analyst %s analyst\n' "$admin_token" "$PASSWORD_USER" >&"${AUTH[1]}"
    read -r -u "${AUTH[0]}" create_line_two
    echo "accounts: $create_line | $create_line_two"
    auth_input="${AUTH[1]}"
    exec {auth_input}>&-
    wait "$AUTH_PID" || true
    register a open a-1 alice asset-1 TICKET-1 1800000000 >/dev/null
    echo "rec line one" | $WORK/shell_record record "$WORK/a-1.rec" 1800000000 10 --tenant a --session a-1 >/dev/null
    register a close a-1 user_close "$WORK/a-1.rec"
    register a open a-2 alice asset-1 TICKET-1 1800000100 >/dev/null
    printf 'x\n' | $WORK/shell_record record "$WORK/a-3.rec" 1800000200 10 --tenant a --session a-3 >/dev/null
    register a open a-3 alice asset-1 TICKET-1 1800000200 >/dev/null
    register a close a-3 user_close "$WORK/a-3.rec"
    for i in 4 5 6 7; do register a open "a-$i" alice asset-1 TICKET-1 "$((1800000200 + i))" >/dev/null; done
    register a open "a-8" 'auth0|a+b/c=d' asset-2 TICKET-1 1800000300 >/dev/null
    printf 'x\n' | $WORK/shell_record record "$WORK/b-1.rec" 1800000000 10 --tenant b --session b-1 >/dev/null
    register b open b-1 alice asset-1 TICKET-1 1800000000 >/dev/null
    register b close b-1 user_close "$WORK/b-1.rec"
    register b open a-1 alice asset-1 TICKET-1 1800000050 >/dev/null
    for tenant in a b; do
        port=$PORT_A
        [[ "$tenant" == b ]] && port=$PORT_B
        cat >"$WORK/$tenant.yaml" <<YAML
name: remote-shell
version: "1"
tenant: $tenant
listen: "127.0.0.1:$port"
settings:
  accounts_store: $WORK/accounts.json
  audit_log: $WORK/api-audit-$tenant.log
  key_file: $WORK/store.key
  compromised_list: $WORK/compromised.txt
  pg_settings: $WORK/pg.yaml
  rate_max_requests: 1000
YAML
        setsid timeout 1500 $WORK/rshell_api "$WORK/$tenant.yaml" >"$WORK/api-$tenant.log" 2>&1 </dev/null &
    done
    for i in $(seq 60); do
        [[ -n "$(token_of $PORT_A auditor)" && -n "$(token_of $PORT_B auditor)" ]] && break
        sleep 1
    done
    echo "rows: $(sql "SELECT tenant || ':' || count(*) FROM remote_shell_sessions GROUP BY tenant ORDER BY tenant" | tr '\n' ' ')"
    ;;
refused)
    token="$(token_of $PORT_A auditor)"
    huge="$(printf '1%.0s' $(seq 3000))"
    for query in 'limit=201' 'limit=%2B5' 'limit=0' 'limit=' 'open=1' 'open=TRUE' 'tenant=b' 'asset=-x' 'requester=a%20b' 'cursor=junk' "cursor=$huge" 'cursor=1800000000.-x' 'limit=1&limit=2'; do
        check "400 for ?$query" 400 "$(status $PORT_A "/remote-shell/sessions?$query" "$token")"
    done
    for id in '-x' '%00' '%FF' "$(printf 'a%.0s' $(seq 129))"; do
        check "404 for id $id" 404 "$(status $PORT_A "/remote-shell/sessions/$id" "$token")"
    done
    analyst="$(token_of $PORT_A analyst)"
    check "analyst 403 (list)" 403 "$(status $PORT_A /remote-shell/sessions "$analyst")"
    check "analyst 403 (detail)" 403 "$(status $PORT_A /remote-shell/sessions/a-1 "$analyst")"
    check "no token 401" 401 "$(anonymous_status $PORT_A /remote-shell/sessions)"
    ;;
good)
    token="$(token_of $PORT_A auditor)"
    check "list a" 200 "$(status $PORT_A '/remote-shell/sessions?limit=200' "$token")"
    check "detail a-1" 200 "$(status $PORT_A /remote-shell/sessions/a-1 "$token")"
    check "unknown id 404" 404 "$(status $PORT_A /remote-shell/sessions/nope "$token")"
    ;;
attacks)
    token_a="$(token_of $PORT_A auditor)"
    token_b="$(token_of $PORT_B auditor)"
    page="$(body $PORT_A '/remote-shell/sessions?limit=200' "$token_a")"
    echo "$page" | jq -c '.items[] | [.session_id, .requester, .asset, .opened_at, .closed_at, .close_reason, .recording_frames, .recording_hash, .recording_bytes]'
    check "tenant a ids" "a-1 a-2 a-3 a-4 a-5 a-6 a-7 a-8" "$(echo "$page" | jq -r '[.items[].session_id] | sort | join(" ")')"
    check "tenant b ids" "a-1 b-1" "$(body $PORT_B '/remote-shell/sessions?limit=200' "$token_b" | jq -r '[.items[].session_id] | sort | join(" ")')"
    check "b does not see a-3" 404 "$(status $PORT_B /remote-shell/sessions/a-3 "$token_b")"
    check "a does not see b-1" 404 "$(status $PORT_A /remote-shell/sessions/b-1 "$token_a")"
    check "same id a-1 differs by tenant" "1800000050" "$(body $PORT_B /remote-shell/sessions/a-1 "$token_b" | jq -r '.opened_at | fromdate')"
    echo "detail a-1: $(body $PORT_A /remote-shell/sessions/a-1 "$token_a")"
    check "a-1 recording hash is 64 hex" 64 "$(body $PORT_A /remote-shell/sessions/a-1 "$token_a" | jq -r '.recording_hash | length')"
    path='/remote-shell/sessions?limit=3'
    walked=""
    for round in $(seq 6); do
        page="$(body $PORT_A "$path" "$token_a")"
        walked="$walked $(echo "$page" | jq -r '[.items[].session_id] | join(" ")')"
        cursor="$(echo "$page" | jq -r '.next_cursor // empty')"
        [[ -n "$cursor" ]] || break
        path="/remote-shell/sessions?limit=3&cursor=$(jq -rn --arg c "$cursor" '$c | @uri')"
    done
    check "walk of limit 3 gives all 8 once" "a-1 a-2 a-3 a-4 a-5 a-6 a-7 a-8" "$(tr ' ' '\n' <<<"$walked" | sed '/^$/d' | sort | tr '\n' ' ' | sed 's/ $//')"
    check "open only" "a-2 a-4 a-5 a-6 a-7 a-8" "$(body $PORT_A '/remote-shell/sessions?open=true&limit=200' "$token_a" | jq -r '[.items[].session_id] | sort | join(" ")')"
    check "asset filter" "a-8" "$(body $PORT_A '/remote-shell/sessions?asset=asset-2' "$token_a" | jq -r '[.items[].session_id] | join(" ")')"
    check "requester with punctuation" "a-8" "$(body $PORT_A "/remote-shell/sessions?requester=$(jq -rn --arg c 'auth0|a+b/c=d' '$c | @uri')" "$token_a" | jq -r '[.items[].session_id] | join(" ")')"
    for constraint in $(sql "SELECT conname FROM pg_constraint WHERE conrelid = 'remote_shell_sessions'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%requester%'"); do
        sql "ALTER TABLE remote_shell_sessions DROP CONSTRAINT \"$constraint\""
    done
    sql "INSERT INTO remote_shell_sessions (tenant, session_id, requester, asset, ticket, opened_at) VALUES ('a', 'evil-1', 'ev il MARKER', 'asset-1', 'TICKET-1', 1800000900)"
    page="$(body $PORT_A '/remote-shell/sessions?limit=200' "$token_a")"
    check "hostile row skipped, counted" "1" "$(echo "$page" | jq -r '.skipped')"
    check "hostile text not in the list body" 0 "$(echo "$page" | grep -c MARKER || true)"
    detail="$(body $PORT_A /remote-shell/sessions/evil-1 "$token_a")"
    check "hostile detail is 500" 500 "$(status $PORT_A /remote-shell/sessions/evil-1 "$token_a")"
    check "stored_value code" "stored_value" "$(echo "$detail" | jq -r '.error.code')"
    check "no hostile text in the detail body" 0 "$(echo "$detail" | grep -c MARKER || true)"
    check "no hostile text in any api log line" 0 "$(cat "$WORK/api-a.log" "$WORK/api-b.log" | grep -c MARKER || true)"
    check "no session id in the crate's own log lines" 0 "$(cat "$WORK/api-a.log" "$WORK/api-b.log" | grep 'remote_shell::' | grep -c 'evil-1' || true)"
    echo "crate log lines: $(cat "$WORK/api-a.log" | grep -c 'remote_shell::') (categories: $(cat "$WORK/api-a.log" | grep 'remote_shell::' | jq -r '.category // .skipped' | sort | uniq -c | tr '\n' ' '))"
    echo "api log tail:"
    tail -4 "$WORK/api-a.log" | cut -c1-200
    echo "failures=$failures"
    ;;
esac
[[ "$phase" == setup || "$failures" -eq 0 ]] || exit 1
