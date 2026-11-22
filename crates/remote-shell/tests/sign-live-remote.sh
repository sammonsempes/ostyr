#!/usr/bin/env bash
# Runs on the client VM of a datastore-pair lab, driven by sign-live.sh: state in $WORK, scratch database $DATABASE.
set -euo pipefail

set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
export PGPASSWORD="$POSTGRES_PASSWORD" PGSSLMODE=verify-full PGSSLROOTCERT=/etc/ostyr-lab/ca.pem
sql() { psql -X -q -tA -v ON_ERROR_STOP=1 -h "$DATASTORE_DOMAIN" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$DATABASE" -c "$1"; }
register() { "$WORK/rshell_register" "$WORK/pg.yaml" "$@"; }
sign() { "$WORK/rshell_sign" "$WORK/pg.yaml" "$1" "$SEED" shell-key "$WORK/seq" "${@:2}"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}

mkdir -p "$WORK/seq"
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
keygen="$("$WORK/command_tool" keygen)"
SEED="$(awk '$1 == "seed" {print $2}' <<<"$keygen")"
public="$(awk '$1 == "public" {print $2}' <<<"$keygen")"
cat >"$WORK/keys.yaml" <<YAML
keys:
  - id: shell-key
    class: sensitive
    public_key: $public
    not_before: 0
    not_after: 4000000000
    actions: [open_shell]
YAML
now="$(date +%s)"
register a open s-1 alice host-7 INC-1 "$now" >/dev/null

echo "== happy path: sign, verify with agent-command, record, sequence"
out="$(sign a s-1 host-7=agent-a low)"
echo "$out" | cut -c1-120
envelope="$(sed -n 's/^signed agent=agent-a envelope=//p' <<<"$out")"
check "signed for agent-a" "agent-a" "$(sed -n 's/^signed agent=\([^ ]*\) .*/\1/p' <<<"$out")"
verdicts="$(printf '%s\n%s\n' "$envelope" "$envelope" | "$WORK/command_tool" verify "$WORK/keys.yaml" "$WORK/state" "$WORK/audit" agent-a a 2>/dev/null)"
check "command_tool accepts the envelope" "accepted open_shell" "$(sed -n 1p <<<"$verdicts")"
check "command_tool refuses its replay" "refused" "$(sed -n 2p <<<"$verdicts" | cut -d' ' -f1)"
check "recorded row" "s-1|agent-a||14400|900|shell-key|1" "$(sql "SELECT session_id || '|' || agent_id || '|' || approvers || '|' || max_seconds || '|' || idle_seconds || '|' || key_id || '|' || sequence FROM remote_shell_signed WHERE tenant = 'a' AND session_id = 's-1'")"
check "recorded expiry is issue plus 60" "60" "$(sql "SELECT expires_at - issued_at FROM remote_shell_signed WHERE session_id = 's-1'")"
check "allocator file" "1" "$(cat "$WORK/seq/agent-a.seq")"

echo "== attack: a second signature of a signed session, from the same or another agent"
check "same session again" "refused: the session is already signed" "$(sign a s-1 host-7=agent-a low 2>&1 || true)"
check "same session for another agent" "refused: the session is already signed" "$(sign a s-1 host-7=agent-b low 2>&1 || true)"
check "still one row, one sequence" "1|1" "$(sql "SELECT count(*) || '|' || max(sequence) FROM remote_shell_signed WHERE session_id = 's-1'")"

echo "== attack: a closed row"
register a open s-2 alice asset-1 TICKET-1 "$now" >/dev/null
printf 'x\n' | "$WORK/shell_record" record "$WORK/s-2.rec" "$now" 10 --tenant a --session s-2 >/dev/null
register a close s-2 user_close "$WORK/s-2.rec" >/dev/null
check "closed row refused" "refused: the session is closed" "$(sign a s-2 asset-1=agent-a low 2>&1 || true)"
check "the claim function refuses a closed row" "0" "$(sql "SELECT count(*) FROM remote_shell_sign_claim('a', 's-2', 'alice', 'asset-1', 'TICKET-1', $now, 'agent-a', '', 14400, 900, $now, $((now + 60)), 'shell-key', 16)")"
register a open s-2b alice host-7 INC-1 "$now" >/dev/null
check "the claim function refuses another requester" "0" "$(sql "SELECT count(*) FROM remote_shell_sign_claim('a', 's-2b', 'mallory', 'host-7', 'INC-1', $now, 'agent-a', '', 14400, 900, $now, $((now + 60)), 'shell-key', 16)")"
check "the claim function refuses a row of another open time" "0" "$(sql "SELECT count(*) FROM remote_shell_sign_claim('a', 's-2b', 'alice', 'host-7', 'INC-1', $((now - 1)), 'agent-a', '', 14400, 900, $now, $((now + 60)), 'shell-key', 16)")"
check "the claim function refuses another tenant" "0" "$(sql "SELECT count(*) FROM remote_shell_sign_claim('b', 's-2b', 'alice', 'host-7', 'INC-1', $now, 'agent-a', '', 14400, 900, $now, $((now + 60)), 'shell-key', 16)")"
check "no row for the refused ones" "1" "$(sql "SELECT count(*) FROM remote_shell_signed")"

echo "== attack: a row older than the delay, a leading dash, an unknown asset, another tenant"
register a open s-3 alice host-7 INC-1 "$((now - 300))" >/dev/null
check "stale row" "refused: the row is older than the signing delay" "$(sign a s-3 host-7=agent-a low 2>&1 || true)"
check "register refuses a requester with a leading dash" "field \`requester\` is outside its grammar" "$(register a open s-4 -mallory host-7 INC-1 "$now" 2>&1 | grep -o 'field .requester. is outside its grammar' | head -1)"
check "no row for the dash requester" "0" "$(sql "SELECT count(*) FROM remote_shell_sessions WHERE session_id = 's-4'")"
register a open s-5 alice host-7 INC-1 "$now" >/dev/null
check "unknown asset" "refused: no agent is declared for the asset" "$(sign a s-5 other-asset=agent-a low 2>&1 || true)"
check "another tenant never sees the session" "refused: unknown session" "$(sign b s-5 host-7=agent-a low 2>&1 || true)"
check "none of them was recorded" "1" "$(sql "SELECT count(*) FROM remote_shell_signed")"

echo "== attack: a denied decision (critical asset, no approver) and a dash approver"
check "critical without approval" "refused: the opening is refused: approval_required" "$(sign a s-5 host-7=agent-a critical 2>&1 || true)"
check "approver with a leading dash" "refused: a shell approver is invalid" "$(sign a s-5 host-7=agent-a critical -bob 2>&1 || true)"
check "still nothing recorded" "1" "$(sql "SELECT count(*) FROM remote_shell_signed")"
out="$(sign a s-5 host-7=agent-a critical bob)"
check "critical with an approver signs it" "bob" "$(sql "SELECT approvers FROM remote_shell_signed WHERE session_id = 's-5'")"
check "sequence advanced for agent-a" "2" "$(cat "$WORK/seq/agent-a.seq")"

echo "== attack: the gate full (16 entries of the tenant in the process gate)"
register a open s-6 alice host-7 INC-1 "$now" >/dev/null
before_sequence="$(cat "$WORK/seq/agent-a.seq")"
check "full gate refuses by name" "refused: the tenant holds too many shell sessions" "$(RSHELL_SIGN_FILL_GATE=16 sign a s-6 host-7=agent-a low 2>&1 || true)"
check "allocator untouched" "$before_sequence" "$(cat "$WORK/seq/agent-a.seq")"
check "the session stays burnt" "refused: the session is already signed" "$(sign a s-6 host-7=agent-a low 2>&1 || true)"

echo "== attack: eight concurrent calls for one session"
register a open s-7 alice host-7 INC-1 "$now" >/dev/null
for i in $(seq 8); do
    sign a s-7 host-7=agent-c low >"$WORK/concurrent-$i.out" 2>&1 &
done
wait
check "exactly one envelope" "1" "$(cat "$WORK"/concurrent-*.out | grep -c '^signed')"
check "the seven others are refused as signed" "7" "$(cat "$WORK"/concurrent-*.out | grep -c '^refused: the session is already signed')"
check "one record, one sequence" "1|1" "$(sql "SELECT count(*) || '|' || count(sequence) FROM remote_shell_signed WHERE session_id = 's-7'")"

echo "== attack: the per-tenant cap of 16 unexpired signed shells"
for i in $(seq 17); do register capt open "c-$i" alice host-7 INC-1 "$now" >/dev/null; done
for i in $(seq 16); do sign capt "c-$i" host-7=agent-d low >/dev/null; done
check "the seventeenth is refused" "refused: the tenant holds too many signed shells" "$(sign capt c-17 host-7=agent-d low 2>&1 || true)"
check "sixteen rows" "16" "$(sql "SELECT count(*) FROM remote_shell_signed WHERE tenant = 'capt'")"
sql "SELECT 1 WHERE pg_advisory_unlock_all() IS NULL" >/dev/null
echo "an expired row frees a place: expire one and sign the seventeenth"
sql "ALTER TABLE remote_shell_signed DISABLE TRIGGER remote_shell_signed_append_once"
sql "UPDATE remote_shell_signed SET issued_at = issued_at - 100, expires_at = issued_at - 50 WHERE tenant = 'capt' AND session_id = 'c-1'"
sql "ALTER TABLE remote_shell_signed ENABLE TRIGGER remote_shell_signed_append_once"
check "the seventeenth is signed after an expiry" "signed" "$(sign capt c-17 host-7=agent-d low 2>&1 | cut -d' ' -f1)"

echo "== attack: the signed rows are append-only"
check "update refused" "1" "$(sql "UPDATE remote_shell_signed SET agent_id = 'x'" 2>&1 | grep -c 'written once')"
check "sequence rewrite refused" "1" "$(sql "UPDATE remote_shell_signed SET sequence = 99 WHERE session_id = 's-1'" 2>&1 | grep -c 'written once')"
check "delete refused" "1" "$(sql "DELETE FROM remote_shell_signed" 2>&1 | grep -c 'never deleted')"
check "truncate refused" "1" "$(sql "TRUNCATE remote_shell_signed" 2>&1 | grep -c 'never deleted')"

echo "== attack: no field value in a refusal"
register a open s-MARKERX alice host-7 INC-1 "$((now - 300))" >/dev/null
register a open s-MARKERY mallory-MARKERX asset-MARKERX INC-MARKERX "$now" >/dev/null
register a open s-MARKERZ mallory-MARKERX asset-MARKERX INC-MARKERX "$now" >/dev/null
leak="$( { sign a s-MARKERX host-7=agent-a low; sign a s-MARKERY other=agent-a low; sign a s-MARKERZ asset-MARKERX=agent-a critical -MARKERX; sign b s-MARKERY asset-MARKERX=agent-a low; register a open -MARKERX alice host-7 INC-1 "$now"; register a open s-MARKERW -MARKERX host-7 INC-1 "$now"; } 2>&1 || true)"
echo "$leak"
check "no marker in any refusal" "0" "$(grep -c MARKERX <<<"$leak" || true)"

echo "failures: $failures"
exit "$failures"
