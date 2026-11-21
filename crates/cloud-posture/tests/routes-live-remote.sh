#!/usr/bin/env bash
# Runs on the client VM of a datastore-pair lab, driven by routes-live.sh: phases setup | refused | good | attacks, state in $WORK.
set -euo pipefail

phase="${1:?phase}"
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
export PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full PGSSLROOTCERT=/etc/ostyr-lab/ca.pem
sql() { psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" -c "$1"; }
posture() { "$WORK/posture_store" "$WORK/pg.yaml" "$@" 2>&1; }
PORT_A=${PORT_BASE}
PORT_B=$((PORT_BASE + 1))
PASSWORD_USER="lab-quartz-harbor-77-ok"
NOW=1700000000000000
ACCOUNT=acct-1
HOSTILE=123456789012
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
token_of() { curl -s -X POST "http://127.0.0.1:$1/auth/login" -H 'content-type: application/json' -d "{\"username\":\"$2\",\"password\":\"$PASSWORD_USER\"}" | jq -r '.token // empty'; }
status() { curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $3" "http://127.0.0.1:$1$2"; }
body() { curl -s -H "authorization: Bearer $3" "http://127.0.0.1:$1$2"; }
anonymous_status() { curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1$2"; }
route() { printf '/posture/accounts/%s/findings%s' "$1" "$2"; }
uri() { jq -rn --arg c "$1" '$c | @uri'; }
digest() { sha256sum | cut -d' ' -f1; }

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
    tool() { "$WORK/auth_tool" "$WORK/accounts.json" "$WORK/auth-audit.log" "$WORK/store.key" "$WORK/compromised.txt" "$@"; }
    bootstrap_output="$(tool <<<"bootstrap admin $PASSWORD_USER")"
    secret="$(awk '$1 == "secret" {print $2}' <<<"$bootstrap_output")"
    code="$(tool <<<"totp $secret")"
    coproc AUTH { tool; }
    printf 'login admin %s 127.0.0.1 %s\n' "$PASSWORD_USER" "$code" >&"${AUTH[1]}"
    read -r -u "${AUTH[0]}" login_line
    admin_token="${login_line##* }"
    printf 'create %s analyst %s analyst\n' "$admin_token" "$PASSWORD_USER" >&"${AUTH[1]}"
    read -r -u "${AUTH[0]}" create_line
    printf 'create %s reader %s reader\n' "$admin_token" "$PASSWORD_USER" >&"${AUTH[1]}"
    read -r -u "${AUTH[0]}" create_line_two
    echo "accounts: $create_line | $create_line_two"
    auth_input="${AUTH[1]}"
    exec {auth_input}>&-
    wait "$AUTH_PID" || true
    posture migrate
    posture bulk a $ACCOUNT run-a1 $NOW 10 a1
    posture bulk b $ACCOUNT run-b1 $NOW 3 b1
    posture bulk b only-b run-b1 $NOW 2 bo
    jq '[.[1]]
        | .[0].finding_info.title = "T\u001b[31m\u009b\u007f‮ㅤ\\[5 bytes cut]"
        | .[0].finding_info.uid = "uid-\u001b[0m‮"
        | .[0].status_detail = ("\u001b" + ([range(1500)] | map("x") | join("")))' "$WORK/prowler-aws-iam-inline.json" >"$WORK/hostile.json"
    posture store a $HOSTILE run-h $NOW "$WORK/hostile.json"
    posture store a default run-k $NOW "$WORK/prowler-k3s-ocsf.json"
    for tenant in a b; do
        port=$PORT_A
        [[ "$tenant" == b ]] && port=$PORT_B
        cat >"$WORK/$tenant.yaml" <<YAML
name: cloud-posture
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
        setsid timeout 1500 "$WORK/posture_api" "$WORK/$tenant.yaml" >"$WORK/api-$tenant.log" 2>&1 </dev/null &
    done
    for i in $(seq 60); do
        [[ -n "$(token_of $PORT_A analyst)" && -n "$(token_of $PORT_B analyst)" ]] && break
        sleep 1
    done
    echo "rows: $(sql "SELECT tenant || '/' || account || ':' || count(*) FROM cloud_posture_findings GROUP BY tenant, account ORDER BY 1" | tr '\n' ' ')"
    ;;
refused)
    token="$(token_of $PORT_A analyst)"
    huge="$(printf '1%.0s' $(seq 3000))"
    for query in 'limit=501' 'limit=%2B5' 'limit=0' 'limit=' 'limit=1.5' 'tenant=b' 'other=1' 'cursor=junk' "cursor=$huge" 'cursor=run-a1%201%203%20abc' 'limit=1&limit=2'; do
        check "400 for ?$query" 400 "$(status $PORT_A "$(route $ACCOUNT "?$query")" "$token")"
    done
    for account in '-x' '%00' '%FF' 'a%20b' "$(printf 'a%.0s' $(seq 257))"; do
        check "404 for account $account" 404 "$(status $PORT_A "$(route "$account" '')" "$token")"
    done
    reader="$(token_of $PORT_A reader)"
    check "reader 403" 403 "$(status $PORT_A "$(route $ACCOUNT '')" "$reader")"
    check "no token 401" 401 "$(anonymous_status $PORT_A "$(route $ACCOUNT '')")"
    ;;
good)
    token="$(token_of $PORT_A analyst)"
    check "page of a" 200 "$(status $PORT_A "$(route $ACCOUNT '')" "$token")"
    check "unknown account is 200 with run null" "null" "$(body $PORT_A "$(route nobody '')" "$token" | jq -c '.run')"
    ;;
attacks)
    token_a="$(token_of $PORT_A analyst)"
    token_b="$(token_of $PORT_B analyst)"
    page="$(body $PORT_A "$(route $ACCOUNT '?limit=500')" "$token_a")"
    echo "$page" | jq -c '.run'
    check "tenant a has 10 rows" 10 "$(echo "$page" | jq '.items | length')"
    check "tenant b has 3 rows for the same account id" 3 "$(body $PORT_B "$(route $ACCOUNT '')" "$token_b" | jq '.items | length')"
    check "b rows carry b's run" "run-b1" "$(body $PORT_B "$(route $ACCOUNT '')" "$token_b" | jq -r '.run.run_id')"
    check "a with ?tenant=b is 400" 400 "$(status $PORT_A "$(route $ACCOUNT '?tenant=b')" "$token_a")"
    check "no b row in a's body" 0 "$(echo "$page" | jq -r '.items[].uid' | grep -c '^b1-' || true)"
    path="$(route $ACCOUNT '?limit=3')"
    walked=""
    for round in $(seq 6); do
        page="$(body $PORT_A "$path" "$token_a")"
        walked="$walked $(echo "$page" | jq -r '[.items[].uid] | join(" ")')"
        cursor="$(echo "$page" | jq -r '.next_cursor // empty')"
        [[ -n "$cursor" ]] || break
        path="$(route $ACCOUNT "?limit=3&cursor=$(uri "$cursor")")"
    done
    check "walk of limit 3 gives 10 distinct uids" 10 "$(tr ' ' '\n' <<<"$walked" | sed '/^$/d' | sort -u | wc -l)"
    check "walk order is severity then identity" "$(body $PORT_A "$(route $ACCOUNT '?limit=500')" "$token_a" | jq -r '[.items[].uid] | join(" ")')" "$(echo $walked)"
    unknown="$(body $PORT_A "$(route nobody '')" "$token_a")"
    foreign="$(body $PORT_A "$(route only-b '')" "$token_a")"
    check "unknown account and b's account give identical bodies" "$(echo "$unknown" | digest)" "$(echo "$foreign" | digest)"
    check "that body is run null, no items" '{"run":null,"unservable":0,"items":[],"next_cursor":null}' "$(echo "$foreign" | jq -c .)"
    b_page="$(body $PORT_B "$(route $ACCOUNT '?limit=1')" "$token_b")"
    b_cursor="$(echo "$b_page" | jq -r '.next_cursor')"
    a_page="$(body $PORT_A "$(route $ACCOUNT '?limit=1')" "$token_a")"
    a_cursor="$(echo "$a_page" | jq -r '.next_cursor')"
    replayed="$(body $PORT_A "$(route $ACCOUNT "?cursor=$(uri "$b_cursor")")" "$token_a")"
    on_unknown="$(body $PORT_A "$(route nobody "?cursor=$(uri "$a_cursor")")" "$token_a")"
    check "b's cursor replayed by a is 409" 409 "$(status $PORT_A "$(route $ACCOUNT "?cursor=$(uri "$b_cursor")")" "$token_a")"
    check "a's cursor on an account with no run is 409" 409 "$(status $PORT_A "$(route nobody "?cursor=$(uri "$a_cursor")")" "$token_a")"
    check "both 409 bodies are byte-equal" "$(echo "$replayed" | digest)" "$(echo "$on_unknown" | digest)"
    posture bulk a $ACCOUNT run-a2 $((NOW + 1)) 10 a2 >/dev/null
    stale="$(body $PORT_A "$(route $ACCOUNT "?cursor=$(uri "$a_cursor")")" "$token_a")"
    check "a cursor is 409 after a replace" 409 "$(status $PORT_A "$(route $ACCOUNT "?cursor=$(uri "$a_cursor")")" "$token_a")"
    check "the replace 409 body is the same" "$(echo "$replayed" | digest)" "$(echo "$stale" | digest)"
    check "the new run is served" "run-a2" "$(body $PORT_A "$(route $ACCOUNT '')" "$token_a" | jq -r '.run.run_id')"
    hostile_raw="$(curl -s -H "authorization: Bearer $token_a" "http://127.0.0.1:$PORT_A$(route $HOSTILE '')")"
    echo "hostile body: $hostile_raw"
    check "hostile body is pure ASCII" 0 "$(printf '%s' "$hostile_raw" | LC_ALL=C grep -cP '[^\x20-\x7e]' || true)"
    check "uid is escaped" 'uid-\u{1b}[0m\u{202e}' "$(echo "$hostile_raw" | jq -r '.items[0].uid')"
    check "title is escaped, forged marker inert" 'T\u{1b}[31m\u{9b}\u{7f}\u{202e}\u{3164}\u{5c}[5 bytes cut]' "$(echo "$hostile_raw" | jq -r '.items[0].title')"
    check "detail cut is visible" '\[477 bytes cut]' "$(echo "$hostile_raw" | jq -r '.items[0].detail | .[-16:]')"
    check "detail_cut" 477 "$(echo "$hostile_raw" | jq -r '.items[0].detail_cut')"
    k3s="$(body $PORT_A "$(route default '?limit=500')" "$token_a")"
    echo "k3s body bytes at limit 500: $(printf "%s" "$k3s" | wc -c)"
    echo "k3s run: $(echo "$k3s" | jq -c '.run | {items, unparsable, bad_field}') served: $(echo "$k3s" | jq '.items | length') unservable: $(echo "$k3s" | jq '.unservable') next: $(echo "$k3s" | jq -r '.next_cursor')"
    check "k3s body is pure ASCII" 0 "$(printf '%s' "$k3s" | LC_ALL=C grep -cP '[^\x20-\x7e]' || true)"
    check "no credential-looking value in the served k3s texts" 0 "$(echo "$k3s" | jq -r '.items[] | .title, .detail, .uid' | grep -cE 'AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|[A-Za-z0-9+/]{40,}' || true)"
    echo "k3s texts naming secrets (check names, no values): $(echo "$k3s" | jq -r '.items[] | .detail' | grep -ciE 'password|secret|token' || true)"
    echo "audit records of reads (tenant a, last 4):"
    grep '"target":"GET /posture' "$WORK/api-audit-a.log" | tail -4 | jq -c '[.action, .actor_id, .tenant, .target, .outcome, .parameters.status]'
    check "audit lines hold no account, cursor or query" 0 "$(grep -cE "$ACCOUNT|$HOSTILE|nobody|only-b|cursor|run-a" "$WORK/api-audit-a.log" || true)"
    check "the reader's 403 left an audit record" true "$(grep '"target":"GET /posture' "$WORK/api-audit-a.log" | grep -q '"outcome":"denied"' && echo true || echo false)"
    check "audit lines hold no query string" 0 "$(grep -c 'limit=' "$WORK/api-audit-a.log" || true)"
    check "no store text in any api log line" 0 "$(cat "$WORK/api-a.log" "$WORK/api-b.log" | grep -c 'uid-' || true)"
    echo "crate log lines: $(grep -c 'cloud_posture::' "$WORK/api-a.log" || true)"
    echo "failures=$failures"
    ;;
esac
[[ "$phase" == setup || "$failures" -eq 0 ]] || exit 1
