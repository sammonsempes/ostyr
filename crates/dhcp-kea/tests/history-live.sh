#!/usr/bin/env bash
# Usage: crates/dhcp-kea/tests/history-live.sh <lab-state-dir>
# Live check of the dhcp_history_store SQL on the PostgreSQL of a datastore-pair lab (lab/up.sh <task> with LAB_PROFILE=datastore-pair):
# the cap at commit, the eviction order, the counter, tenant isolation and the advisory lock under 8 parallel callers.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lab_state="${1:?usage: history-live.sh <lab-state-dir>}"
read -r _ user address < <(awk '$1 == "datastore"' "$lab_state/vms.txt")
[[ -n "$address" ]] || { echo "no datastore VM in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

scp "${ssh_options[@]}" "$here/migrations/002_dhcp_lease_history.sql" "$here/migrations/003_dhcp_history_eviction.sql" "$here/migrations/004_dhcp_history_lock_64.sql" "$user@$address:/tmp/"
ssh "${ssh_options[@]}" "$user@$address" 'bash -s' <<'REMOTE'
set -euo pipefail
database=history_live_$$
sudo -u postgres createdb "$database"
trap 'sudo -u postgres dropdb --if-exists "$database"' EXIT
run() { sudo -u postgres psql -X -q -tA -v ON_ERROR_STOP=1 -d "$database" "$@"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected $2 got $3"; failures=$((failures + 1)); fi
}
run -f /tmp/002_dhcp_lease_history.sql
run -f /tmp/003_dhcp_history_eviction.sql
run -f /tmp/004_dhcp_history_lock_64.sql

NOW=1700000000
DAY=86400
docs() {
    echo "(SELECT jsonb_agg(jsonb_build_object('identity', 'k$2-' || g, 'address', '10.0.0.5', 'mac', 'AA-BB-CC-DD-EE-01', 'hostname', NULL, 'starts', $2 + g, 'ends', $2 + g + 100, 'action', 'lease-assigned', 'subnet_id', 1)) FROM generate_series(1, $1) g)"
}
store() {
    run -c "SELECT n_expired, n_inserted, n_duplicate, n_refused_full, n_stale, n_evicted, n_pressure FROM dhcp_history_store('$1', coalesce(${4:-NULL}, '[]'::jsonb), $2, 400, $3)"
}
rows() { run -c "SELECT count(*) FROM dhcp_lease_history WHERE tenant = '$1'"; }
counter() { run -c "SELECT coalesce((SELECT total FROM dhcp_history_rows WHERE tenant = '$1'), -1)"; }
bounds() { run -c "SELECT extract(epoch FROM min(ends))::bigint || ':' || extract(epoch FROM max(ends))::bigint FROM dhcp_lease_history WHERE tenant = '$1'"; }

check "fill to the cap: expired|inserted|duplicate|refused_full|stale|evicted|pressure" "0|100|0|0|0|0|0" "$(store acme 100 $NOW "$(docs 100 $NOW)")"
check "rows after fill" 100 "$(rows acme)"
check "counter after fill" 100 "$(counter acme)"
check "10 newer rows evict the 10 oldest" "0|10|0|0|0|10|10" "$(store acme 100 $((NOW + 1000)) "$(docs 10 $((NOW + 1000)))")"
check "cap holds at commit" 100 "$(rows acme)"
check "counter follows eviction" 100 "$(counter acme)"
check "oldest survivor is the 11th, newest is the new batch" "$((NOW + 111)):$((NOW + 1110))" "$(bounds acme)"
check "replay is all duplicate" "0|0|10|0|0|0|0" "$(store acme 100 $((NOW + 1000)) "$(docs 10 $((NOW + 1000)))")"
check "tenant isolation: other tenant starts empty" 0 "$(rows globex)"
check "same identities in another tenant insert" "0|5|0|0|0|0|0" "$(store globex 100 $NOW "$(docs 5 $NOW)")"
check "other tenant did not touch acme" 100 "$(rows acme)"
check "evicting in acme leaves globex whole" "0|10|0|0|0|10|10" "$(store acme 100 $((NOW + 2000)) "$(docs 10 $((NOW + 2000)))")"
check "globex still 5" 5 "$(rows globex)"
check "lowering the cap shrinks to it at the next call" "0|0|0|0|0|50|50" "$(store acme 50 $((NOW + 3000)) "")"
check "acme at the lowered cap" 50 "$(rows acme)"
check "counter at the lowered cap" 50 "$(counter acme)"
check "a batch over the whole cap keeps its newest rows" "0|5|0|5|0|0|0" "$(store tiny 5 $NOW "$(docs 10 $NOW)")"
check "tiny newest rows kept" "$((NOW + 106)):$((NOW + 110))" "$(bounds tiny)"
check "old rows evicted without pressure" "0|5|0|0|0|5|0" "$(store tiny 5 $((NOW + 300 * DAY)) "$(docs 5 $((NOW + 300 * DAY)))")"

BASE=$((NOW + 10000))
check "full tenant of recent rows" "0|100|0|0|0|0|0" "$(store oldt 100 $NOW "$(docs 100 $BASE)")"
check "a batch older than every stored row is refused, nothing evicted" "0|0|0|10|0|0|0" "$(store oldt 100 $NOW "$(docs 10 $NOW)")"
check "old batch left the recent rows" "$((BASE + 101)):$((BASE + 200))" "$(bounds oldt)"
check "old replay again refused" "0|0|0|10|0|0|0" "$(store oldt 100 $NOW "$(docs 10 $NOW)")"
check "recent replay is duplicate" "0|0|10|0|0|0|0" "$(store oldt 100 $NOW "$(docs 10 $BASE)")"
check "old replay refused after the recent one" "0|0|0|10|0|0|0" "$(store oldt 100 $NOW "$(docs 10 $NOW)")"
check "alternating replays leave the recent rows" "100|$((BASE + 101)):$((BASE + 200))" "$(rows oldt)|$(bounds oldt)"
mixed="(SELECT jsonb_agg(x) FROM (SELECT jsonb_array_elements($(docs 5 $NOW)) x UNION ALL SELECT jsonb_array_elements($(docs 3 $((BASE + 1000)))) x) m)"
check "mixed batch: 3 newest stored, 5 old refused, 3 oldest stored evicted" "0|3|0|5|0|3|3" "$(store oldt 100 $NOW "$mixed")"
check "mixed batch keeps the newest of stored plus fresh" "100|$((BASE + 104)):$((BASE + 1103))" "$(rows oldt)|$(bounds oldt)"
check "counter after mixed" 100 "$(counter oldt)"

for caller in 1 2 3 4 5 6 7 8; do
    store par 100 $NOW "$(docs 30 $((NOW + caller * 1000)))" >"/tmp/par-$caller.out" &
done
wait
check "8 parallel callers: rows at the cap" 100 "$(rows par)"
check "8 parallel callers: counter at the cap" 100 "$(counter par)"
check "8 parallel callers: inserted plus refused_full sum" 240 "$(cat /tmp/par-?.out | awk -F"|" '{s += $2 + $4} END {print s}')"
check "8 parallel callers: inserted minus evicted" 100 "$(cat /tmp/par-?.out | awk -F"|" '{s += $2 - $6} END {print s}')"

lock_held() { echo "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND ((classid::bigint << 32) | objid::bigint) = hashtextextended('dhcp_history_store/$1', 0) AND $2)"; }
MAX_POLLS=600
wait_until() {
    local query="$1" attempt
    for attempt in $(seq 1 "$MAX_POLLS"); do
        [[ "$(run -c "$query")" == "t" ]] && return 0
        sleep 0.1
    done
    echo "FAIL timed out waiting for: $query"
    failures=$((failures + 1))
    return 0
}
run -c "CREATE TABLE lock_gate (open boolean NOT NULL); INSERT INTO lock_gate VALUES (false)"
sudo -u postgres psql -X -q -tA -v ON_ERROR_STOP=1 -d "$database" -c "BEGIN; SELECT dhcp_history_store('lock', $(docs 3 $NOW), 100, 400, $NOW); DO \$\$ BEGIN FOR i IN 1..$MAX_POLLS LOOP EXIT WHEN (SELECT open FROM lock_gate); PERFORM pg_sleep(0.1); END LOOP; END \$\$; COMMIT" >/dev/null &
holder=$!
wait_until "$(lock_held lock granted)"
store lock 100 $NOW "$(docs 3 $((NOW + 500)))" >/tmp/lock-second.out &
second=$!
wait_until "$(lock_held lock "NOT granted")"
check "second caller waits on the advisory lock of the first" "advisory" "$(run -c "SELECT wait_event FROM pg_stat_activity WHERE datname = '$database' AND wait_event_type = 'Lock' LIMIT 1")"
run -c "UPDATE lock_gate SET open = true"
wait "$holder" "$second"
check "both callers stored under the lock" 6 "$(rows lock)"
check "lock counter" 6 "$(counter lock)"

check "t1481 and t45040 share the old 32-bit hash" "t" "$(run -c "SELECT hashtext('t1481') = hashtext('t45040')")"
run -c "UPDATE lock_gate SET open = false"
sudo -u postgres psql -X -q -tA -v ON_ERROR_STOP=1 -d "$database" -c "BEGIN; SELECT dhcp_history_store('t1481', $(docs 3 $NOW), 100, 400, $NOW); DO \$\$ BEGIN FOR i IN 1..$MAX_POLLS LOOP EXIT WHEN (SELECT open FROM lock_gate); PERFORM pg_sleep(0.1); END LOOP; END \$\$; COMMIT" >/dev/null &
holder=$!
wait_until "$(lock_held t1481 granted)"
other="$(run -c "SET lock_timeout = '20s'; SELECT n_inserted FROM dhcp_history_store('t45040', $(docs 3 $NOW), 100, 400, $NOW)" 2>&1 | tail -1)"
check "a holder of t1481 does not block t45040" 3 "$other"
check "t45040 waited on no lock" "f" "$(run -c "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted)")"
run -c "UPDATE lock_gate SET open = true"
wait "$holder"
check "slash and quote in a tenant name" 3 "$(run -c "SELECT n_inserted FROM dhcp_history_store('a/b''c', $(docs 3 $NOW), 100, 400, $NOW)")"

mismatch="$(run -c "SELECT count(*) FROM (SELECT tenant, count(*) AS n FROM dhcp_lease_history GROUP BY tenant) c JOIN dhcp_history_rows r USING (tenant) WHERE r.total <> c.n")"
check "every counter equals its row count" 0 "$mismatch"
rm -f /tmp/par-?.out /tmp/lock-second.out
echo "failures=$failures"
exit "$failures"
REMOTE
