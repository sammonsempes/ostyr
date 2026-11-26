#!/usr/bin/env bash
# Usage: crates/intel-feeds/tests/bounds-live.sh <lab-state-dir> [scenario...]
# Live check of the document counts and the stored budget on a datastore-pair lab (LAB_PROFILE=datastore-pair lab/up.sh <task>): the musl release binary and the
# intel_read example run on the client VM against the datastore VM; peak RSS is read from /proc, rows are read back from ClickHouse and by intel_read.
# Scenarios: floods (STIX, MISP, JSON documents), files (1M and 6M IPs, FIFO, /dev/zero), rotate (rot), swap (tx, a SIGHUP reload), all (default).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
lab_state="${1:?usage: bounds-live.sh <lab-state-dir> [scenario...]}"
shift
scenarios="${*:-all}"
read -r _ client_user client_address < <(awk '$1 == "client"' "$lab_state/vms.txt")
[[ -n "$client_address" ]] || { echo "a client VM is required in $lab_state/vms.txt" >&2; exit 2; }
ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
musl="$here/target/x86_64-unknown-linux-musl/release"
[[ -x "$musl/ostyr-intel" && -x "$musl/examples/intel_read" ]] || { echo "build first: cargo build --release --target x86_64-unknown-linux-musl -p intel-feeds --bins --examples" >&2; exit 2; }
scp "${ssh_options[@]}" "$musl/ostyr-intel" "$musl/examples/intel_read" "$client_user@$client_address:/tmp/" >/dev/null

ssh "${ssh_options[@]}" "$client_user@$client_address" "SCENARIOS='$scenarios' bash -s" <<'REMOTE'
set -euo pipefail
set -a
source <(sudo cat /etc/ostyr-lab/datastore.env)
set +a
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
umask 077
printf '%s' "$CLICKHOUSE_PASSWORD" >ch.pw
url="https://$DATASTORE_DOMAIN:$CLICKHOUSE_HTTPS_PORT"
ch() { curl -sS --fail-with-body --cacert /etc/ostyr-lab/ca.pem -u "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" "$url/" --data-binary "$1"; }
failures=0
check() {
    if [[ "$2" == "$3" ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected [$2] got [$3]"; failures=$((failures + 1)); fi
}
wanted() { [[ " $SCENARIOS " == *" all "* || " $SCENARIOS " == *" $1 "* ]]; }

ips() {
    awk -v n="$1" -v o="$2" 'BEGIN { for (i = 0; i < n; i++) { x = i + o; printf "%d.%d.%d.%d\n", 11 + int(x / 16777216) % 200, int(x / 65536) % 256, int(x / 256) % 256, x % 256 } }'
}

clickhouse_block() {
    cat <<YAML
clickhouse:
  url: $url
  user: $CLICKHOUSE_USER
  password_file: $work/ch.pw
  ca_file: /etc/ostyr-lab/ca.pem
  database: ostyr
  table: iocs
  dictionary: ioc_trie
  dictionary_user: ostyr_dict
  dictionary_port: 9440
  tenant: tenant-a
YAML
}

feed_entry() {
    printf '  - name: %s\n    format: %s\n    path: %s\n    ttl_seconds: 2000000000\n' "$1" "$2" "$3"
    if [[ "$2" == json ]]; then printf '    mapping:\n      value: ioc\n'; fi
}

settings_for() {
    local dir=$1
    mkdir -p "$dir"
    printf 'feeds_file: %s/feeds.yaml\naudit_file: %s/audit.jsonl\ninterval_seconds: 60\n' "$dir" "$dir" >"$dir/service.yaml"
    [[ -s "$dir/good.txt" ]] || printf '192.0.2.1\n198.51.100.0/24\n' >"$dir/good.txt"
}

write_feeds() {
    local dir=$1
    shift
    {
        printf 'feeds:\n'
        printf '%s\n' "$@"
        clickhouse_block
    } >"$dir/feeds.yaml"
}

one_round() {
    local dir=$1 pid peak=0 rss
    /tmp/ostyr-intel "$dir/service.yaml" 2>"$dir/run.log" &
    pid=$!
    for _ in $(seq 1 600); do
        rss="$(awk '/^VmHWM:/ { print $2 }' "/proc/$pid/status" 2>/dev/null || echo 0)"
        [[ "${rss:-0}" -gt "$peak" ]] && peak="$rss"
        grep -q 'intel round' "$dir/run.log" && break
        sleep 0.5
    done
    rss="$(awk '/^VmHWM:/ { print $2 }' "/proc/$pid/status" 2>/dev/null || echo 0)"
    [[ "${rss:-0}" -gt "$peak" ]] && peak="$rss"
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    echo "peak RSS $((peak / 1024)) MB"
    { grep -E 'intel (round|feed failed|feeds left|service)|feed skipped|ERROR' "$dir/run.log" || true; } | cut -c1-420
    echo "$((peak / 1024))" >"$dir/peak_mb"
}

reset_table() {
    ch "CREATE DATABASE IF NOT EXISTS ostyr" >/dev/null
    ch "TRUNCATE TABLE IF EXISTS ostyr.iocs" >/dev/null
}

live_rows() { ch "SELECT count() FROM ostyr.iocs FINAL WHERE tenant = 'tenant-a' AND expires_at > now()"; }

read_back() {
    local dir=$1
    /tmp/intel_read "$dir/feeds.yaml" >"$dir/read.out" 2>"$dir/read.err" && echo "intel_read ok: $(tail -1 "$dir/read.err")" || echo "intel_read FAILED: $(tail -1 "$dir/read.err")"
}

if wanted floods; then
    echo "=== floods: documents of 64 MiB of tiny elements"
    d="$work/floods"
    settings_for "$d"
    awk 'BEGIN { printf "{\"objects\":["; for (i = 0; i < 9000000; i++) printf "{\"\":0},"; print "{}]}" }' >"$d/stix_empty_key.json"
    awk 'BEGIN { printf "{\"objects\":["; for (i = 0; i < 22000000; i++) printf "{},"; print "{}]}" }' >"$d/stix_braces.json"
    awk 'BEGIN { printf "{\"Event\":{\"Object\":["; for (i = 0; i < 22000000; i++) printf "{},"; print "{}]}}" }' >"$d/misp_objects.json"
    awk 'BEGIN { printf "{\"Event\":{\"Object\":["; for (i = 0; i < 300; i++) { printf "{\"Attribute\":["; for (j = 0; j < 1000; j++) printf "{\"type\":\"ip-dst\",\"value\":\"10.1.%d.%d\",\"to_ids\":true},", i % 250, j % 250; printf "{}]},"; } print "{}]}}" }' >"$d/misp_attributes.json"
    awk 'BEGIN { printf "["; for (i = 0; i < 22000000; i++) printf "0,"; print "0]" }' >"$d/list.json"
    ls -l "$d"/*.json | awk '{ print $5, $9 }'
    write_feeds "$d" "$(feed_entry stix_a stix stix_empty_key.json)" "$(feed_entry stix_b stix stix_braces.json)" "$(feed_entry misp_o misp misp_objects.json)" "$(feed_entry misp_a misp misp_attributes.json)" "$(feed_entry list json list.json)" "$(feed_entry good crowdsec good.txt)"
    reset_table
    one_round "$d"
    check "peak RSS under 600 MB" 1 "$([[ "$(cat "$d/peak_mb")" -lt 600 ]] && echo 1 || echo 0)"
    for name in stix_a stix_b misp_o misp_a list; do
        grep -q "feed=$name .*too_many" "$d/run.log" || grep -q "$name.*too_many_\(objects\|attributes\)" "$d/run.log" && echo "PASS $name named too_many_*" || { echo "FAIL $name not named"; failures=$((failures + 1)); }
    done
    check "good feed loaded" 2 "$(live_rows)"
    read_back "$d"
fi

if wanted files; then
    echo "=== files: 1M and 6M IPs, a FIFO, /dev/zero"
    d="$work/files"
    settings_for "$d"
    ips 1000000 0 >"$d/m1.txt"
    ips 6000000 2000000 >"$d/m6.txt"
    mkfifo "$d/fifo.txt"
    ln -s /dev/zero "$d/zero.txt"
    write_feeds "$d" "$(feed_entry m1 crowdsec m1.txt)" "$(feed_entry m6 crowdsec m6.txt)" "$(feed_entry fifo crowdsec fifo.txt)" "$(feed_entry zero crowdsec zero.txt)" "$(feed_entry good crowdsec good.txt)"
    reset_table
    one_round "$d"
    check "peak RSS under 300 MB" 1 "$([[ "$(cat "$d/peak_mb")" -lt 300 ]] && echo 1 || echo 0)"
    check "named failed feeds" 1 "$(grep -c 'names="m1,m6,fifo,zero"' "$d/run.log")"
    check "good feed loaded" 2 "$(live_rows)"
    read_back "$d"
fi

if wanted rotate; then
    echo "=== rotate: 100000 IPs changing every round, three rounds, intel_read after each"
    d="$work/rotate"
    settings_for "$d"
    reset_table
    for round in 0 1 2 3; do
        ips 100000 "$((round * 100000))" >"$d/rot.txt"
        write_feeds "$d" "$(feed_entry rot crowdsec rot.txt)"
        echo "-- round $round"
        one_round "$d"
        echo "live rows: $(live_rows)"
        read_back "$d"
    done
    check "the tenant never passes the read bound" 1 "$([[ "$(live_rows)" -le 250000 ]] && echo 1 || echo 0)"
    check "the left-out feed is named" 1 "$(grep -c 'stored_ioc_cap' "$d/run.log")"
fi

if wanted swap; then
    echo "=== swap: a reload replaces the feed by one of other values (SIGHUP), two rounds"
    d="$work/swap"
    settings_for "$d"
    ips 100000 0 >"$d/a.txt"
    ips 100000 100000 >"$d/a2.txt"
    ips 100000 5000000 >"$d/b.txt"
    write_feeds "$d" "$(feed_entry a crowdsec a.txt)" "$(feed_entry a2 crowdsec a2.txt)"
    reset_table
    /tmp/ostyr-intel "$d/service.yaml" 2>"$d/run.log" &
    pid=$!
    for _ in $(seq 1 600); do grep -q 'intel round' "$d/run.log" && break; sleep 0.5; done
    echo "live rows after round 1: $(live_rows)"
    write_feeds "$d" "$(feed_entry b crowdsec b.txt)"
    kill -HUP "$pid"
    for _ in $(seq 1 400); do [[ "$(grep -c 'intel round' "$d/run.log")" -ge 2 ]] && break; sleep 0.5; done
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    { grep -E 'intel (round|feed failed|feeds left)|reload' "$d/run.log" || true; } | cut -c1-420
    echo "live rows after round 2: $(live_rows)"
    check "the tenant never passes the read bound" 1 "$([[ "$(live_rows)" -le 250000 ]] && echo 1 || echo 0)"
    read_back "$d"
fi

echo "failures: $failures"
exit "$failures"
REMOTE
