#!/usr/bin/env bash
# Usage (inside the lab VM, as root, with Suricata installed): ndr-eve-follow.sh <follow_eve binary>
# Live proof of the ndr eve.json follower: Suricata writes while the file is moved and Suricata is sent HUP (the follower must return every line once),
# then while it is copytruncated (the lost window is named, `eve_truncated` is counted).
set -euo pipefail

readonly FOLLOW="$1"
readonly BASE=/root/ndr-follow
readonly LOG_DIR=/var/log/suricata
readonly EVE="$LOG_DIR/eve.json"
readonly TICKS=90
readonly TICK_MILLIS=500
readonly ENGINE_ATTEMPTS=30
readonly ROTATE_AFTER_SECONDS=12
readonly SETTLE_SECONDS=8

traffic_pid=""
suricata_pid=""
http_pid=""

cleanup() {
    for pid in "$traffic_pid" "$suricata_pid" "$http_pid"; do
        if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
    done
}
trap cleanup EXIT

start_suricata() {
    rm -f "$EVE" "$EVE".1 "$BASE/suricata.log"
    suricata -c /etc/suricata/suricata.yaml -i lo -k none -l "$LOG_DIR" > "$BASE/suricata.log" 2>&1 &
    suricata_pid=$!
    for _ in $(seq 1 "$ENGINE_ATTEMPTS"); do
        if grep -q "Engine started" "$BASE/suricata.log" 2>/dev/null; then break; fi
        sleep 2
    done
    sleep 3
    (while true; do curl -sS -o /dev/null http://127.0.0.1:8080/benign.txt || true; sleep 0.1; done) &
    traffic_pid=$!
}

stop_suricata() {
    kill "$traffic_pid" 2>/dev/null || true
    sleep "$SETTLE_SECONDS"
    kill -TERM "$suricata_pid" 2>/dev/null || true
    wait "$suricata_pid" 2>/dev/null || true
    traffic_pid=""
    suricata_pid=""
}

run_follower() {
    local state="$1"
    rm -rf "$state"
    mkdir -p "$state"
    chmod 700 "$state"
    "$FOLLOW" "$EVE" "$state" "$TICKS" "$TICK_MILLIS" > "$state.out"
}

rm -rf "$BASE"
mkdir -p "$BASE/web"
printf 'a perfectly benign file\n' > "$BASE/web/benign.txt"
ip link set lo mtu 1500
(cd "$BASE/web" && python3 -m http.server 8080 --bind 127.0.0.1 > "$BASE/http.log" 2>&1) &
http_pid=$!

echo "=== phase A: move rotation then HUP"
start_suricata
for _ in $(seq 1 30); do [[ -s "$EVE" ]] && break; sleep 1; done
run_follower "$BASE/state-a" &
follower_pid=$!
sleep "$ROTATE_AFTER_SECONDS"
mv "$EVE" "$EVE.1"
kill -HUP "$suricata_pid"
sleep "$ROTATE_AFTER_SECONDS"
stop_suricata
wait "$follower_pid"
written_a=$(( $(wc -l < "$EVE.1") + $(wc -l < "$EVE") ))
echo "follower: $(cat "$BASE/state-a.out")"
echo "written (eve.json.1 + eve.json): $written_a"

echo "=== phase B: copytruncate"
start_suricata
for _ in $(seq 1 30); do [[ -s "$EVE" ]] && break; sleep 1; done
run_follower "$BASE/state-b" &
follower_pid=$!
sleep "$ROTATE_AFTER_SECONDS"
cp "$EVE" "$BASE/copy.json"
: > "$EVE"
sleep "$ROTATE_AFTER_SECONDS"
stop_suricata
wait "$follower_pid"
written_b=$(( $(wc -l < "$BASE/copy.json") + $(wc -l < "$EVE") ))
echo "follower: $(cat "$BASE/state-b.out")"
echo "written (copy + eve.json): $written_b"
