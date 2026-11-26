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

run_big_line() {
    local label="$1" size_mb="$2" rotate="$3" ticks="$4"
    local dir="$BASE/big-$label"
    rm -rf "$dir"
    mkdir -p "$dir/state"
    chmod 700 "$dir/state"
    printf 'first\n' > "$dir/eve.json"
    head -c "$((size_mb * 1048576))" /dev/zero | tr '\0' x >> "$dir/eve.json"
    ( /usr/bin/time -v "$FOLLOW" "$dir/eve.json" "$dir/state" "$ticks" 700 > "$dir/out" 2> "$dir/time" ) &
    local follower_pid=$!
    sleep 3
    if [[ "$rotate" == "yes" ]]; then
        mv "$dir/eve.json" "$dir/eve.json.1"
        printf 'second\nthird\n' > "$dir/eve.json"
    elif [[ "$rotate" == "no" ]]; then
        printf '\nafter\n' >> "$dir/eve.json"
    fi
    wait "$follower_pid"
    echo "=== big line $label ($size_mb MiB, rotate=$rotate): $(cat "$dir/out")"
    grep "Maximum resident" "$dir/time"
}

echo "=== phase C: huge lines"
run_big_line plain 300 no 8
run_big_line rotated 300 yes 8
run_big_line endless 2048 never 12
run_big_line huge-rotated 2048 yes 12

run_backlog() {
    local label="$1" mode="$2"
    local dir="$BASE/backlog-$label"
    rm -rf "$dir"
    mkdir -p "$dir/state"
    chmod 700 "$dir/state"
    seq 1 5000 | sed 's/^/a/' > "$dir/eve.json"
    "$FOLLOW" "$dir/eve.json" "$dir/state" 14 700 > "$dir/out" &
    local follower_pid=$!
    sleep 1
    mv "$dir/eve.json" "$dir/eve.json.1"
    if [[ "$mode" == "fifo" ]]; then
        mkfifo "$dir/eve.json"
    else
        seq 1 50 | sed 's/^/b/' > "$dir/eve.json"
        sleep 1.5
        mv "$dir/eve.json" "$dir/eve.json.2"
        seq 1 50 | sed 's/^/c/' > "$dir/eve.json"
    fi
    wait "$follower_pid"
    echo "=== backlog $label: $(cat "$dir/out")"
}

echo "=== phase D: second rotation during a backlog drain (expect lines=5100 rotations=2 successors_missed=0)"
run_backlog double rotate

echo "=== phase E: a FIFO at the path during the drain (expect lines=5000 successors_refused>0)"
run_backlog fifo fifo
