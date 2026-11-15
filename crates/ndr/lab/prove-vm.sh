#!/usr/bin/env bash
# Usage (inside the lab VM, as root, after fetch-yr.sh and with Suricata installed): prove-vm.sh <scan_filestore binary>
# Live proof of the ndr crate: Suricata file-store on loopback, an HTTP download of the EICAR test file and of a benign file, one scan tick with a
# real `yr`, then the attacks: a symlink in the filestore, a 64 MiB file, a slow rule, a `yr` that never exits, a `yr` that prints without end.
set -euo pipefail

readonly SCAN="$1"
readonly BASE=/root/ndr-proof
readonly YR=/usr/local/bin/yr
readonly LOG_DIR=/var/log/suricata
readonly FILESTORE="$LOG_DIR/filestore"
readonly CAPTURE_SECONDS=60
readonly BIG_MIB=64
readonly SLOW_SECONDS=2

rm -rf "$BASE"
mkdir -p "$BASE/rules" "$BASE/rules-slow" "$BASE/web" "$BASE/work"
chmod 700 "$BASE/work"
printf 'rule eicar { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }\n' > "$BASE/rules/eicar.yar"
printf 'rule slow { condition: for any i in (0..2000000000) : ( uint8(i %% 60) > 255 ) }\n' > "$BASE/rules-slow/slow.yar"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$BASE/web/eicar.com"
printf 'a perfectly benign file\n' > "$BASE/web/benign.txt"

ip link set lo mtu 1500
sed -i '/^  - file-store:/,/force-filestore/ { s/enabled: no/enabled: yes/; s/#force-filestore: yes/force-filestore: yes/ }' /etc/suricata/suricata.yaml
rm -rf "$FILESTORE" "$LOG_DIR/eve.json"
timeout "$CAPTURE_SECONDS" suricata -c /etc/suricata/suricata.yaml -i lo -k none -l "$LOG_DIR" > "$BASE/suricata.log" 2>&1 &
suricata_pid=$!
(cd "$BASE/web" && timeout "$CAPTURE_SECONDS" python3 -m http.server 8080 --bind 127.0.0.1 > "$BASE/http.log" 2>&1) &
for _ in $(seq 1 30); do
    if grep -q "Engine started" "$BASE/suricata.log" 2>/dev/null; then break; fi
    sleep 2
done
sleep 5
curl -sS -o /dev/null http://127.0.0.1:8080/eicar.com
curl -sS -o /dev/null http://127.0.0.1:8080/benign.txt
for _ in $(seq 1 15); do
    if [[ "$(grep -c '"stored":true' "$LOG_DIR/eve.json" 2>/dev/null || true)" -ge 2 ]]; then break; fi
    sleep 2
done
wait "$suricata_pid" || true

echo "=== stored fileinfo events"
grep '"stored":true' "$LOG_DIR/eve.json" | cut -c1-200
echo "=== real yr: one tick over the filestore"
"$SCAN" "$YR" "$BASE/work" "$BASE/rules" "$FILESTORE" "$LOG_DIR/eve.json"

hash_of() {
    printf '%s' "$1" | sha256sum | cut -d' ' -f1
}
fileinfo() {
    printf '{"event_type":"fileinfo","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","fileinfo":{"sha256":"%s","stored":true}}\n' "$1"
}

echo "=== attack: symlink to /etc/shadow in the filestore"
link_hash="$(hash_of symlink)"
mkdir -p "$FILESTORE/${link_hash:0:2}"
ln -sf /etc/shadow "$FILESTORE/${link_hash:0:2}/$link_hash"
fileinfo "$link_hash" > "$BASE/eve-link.json"
"$SCAN" "$YR" "$BASE/work" "$BASE/rules" "$FILESTORE" "$BASE/eve-link.json"

echo "=== attack: 64 MiB extracted file"
big_hash="$(hash_of big)"
mkdir -p "$FILESTORE/${big_hash:0:2}"
dd if=/dev/zero of="$FILESTORE/${big_hash:0:2}/$big_hash" bs=1M count="$BIG_MIB" status=none
fileinfo "$big_hash" > "$BASE/eve-big.json"
/usr/bin/time -v "$SCAN" "$YR" "$BASE/work" "$BASE/rules" "$FILESTORE" "$BASE/eve-big.json" 2>&1 | grep -E "counts=|Maximum resident"

echo "=== attack: slow rule on a crafted file, timeout $SLOW_SECONDS s"
slow_hash="$(hash_of slow)"
mkdir -p "$FILESTORE/${slow_hash:0:2}"
printf 'crafted' > "$FILESTORE/${slow_hash:0:2}/$slow_hash"
fileinfo "$slow_hash" > "$BASE/eve-slow.json"
NDR_TIMEOUT_SECS="$SLOW_SECONDS" "$SCAN" "$YR" "$BASE/work" "$BASE/rules-slow" "$FILESTORE" "$BASE/eve-slow.json"
echo "leftover yr processes: $(pgrep -c -x yr || true)"

echo "=== attack: a yr that never exits"
printf '#!/bin/sh\ncase "$1" in\ncompile) : > "$3"; exit 0;;\nscan) exec /bin/sleep 100000;;\nesac\n' > "$BASE/yr-hang"
chmod 755 "$BASE/yr-hang"
NDR_TIMEOUT_SECS="$SLOW_SECONDS" "$SCAN" "$BASE/yr-hang" "$BASE/work" "$BASE/rules" "$FILESTORE" "$BASE/eve-slow.json"
echo "leftover sleep processes: $(pgrep -c -x sleep || true)"
echo "defunct processes: $(ps -eo stat | grep -c '^Z' || true)"

echo "=== attack: a yr that prints without end"
printf '#!/bin/sh\ncase "$1" in\ncompile) : > "$3"; exit 0;;\nscan) exec /usr/bin/yes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;\nesac\n' > "$BASE/yr-flood"
chmod 755 "$BASE/yr-flood"
/usr/bin/time -v "$SCAN" "$BASE/yr-flood" "$BASE/work" "$BASE/rules" "$FILESTORE" "$BASE/eve-slow.json" 2>&1 | grep -E "counts=|Maximum resident"
echo "leftover yes processes: $(pgrep -c -x yes || true)"
echo "private work dir content after the runs: $(find "$BASE/work" -mindepth 1 | wc -l) entries"
