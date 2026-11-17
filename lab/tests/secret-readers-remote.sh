#!/usr/bin/env bash
# Usage (on the lab VM, as a normal user): secret-readers-remote.sh <directory holding auth_tool, oncall_send and oncall_link>
# Proves that the accounts store, the oncall secret files and the acknowledgement-link key go through the checked open: a mode 644 file, a
# symlink to another 600 file, a FIFO and a file of another user are refused, a swap between two runs is caught, a 600 file still works.
set -euo pipefail

readonly DIR="${1:?usage: secret-readers-remote.sh <directory>}"
readonly PASSWORD="correct-horse-battery-staple"
failures=0

check() {
    if [[ "$2" == "$3" ]]; then
        printf 'PASS %s\n' "$1"
    else
        printf 'FAIL %s: got [%s], wanted [%s]\n' "$1" "$2" "$3"
        failures=$((failures + 1))
    fi
}

cd "$DIR"
umask 077
head -c 32 /dev/urandom >key
printf 'passwordpassword\n' >words

store_run() { printf 'bootstrap admin2 %s\n' "$PASSWORD" | timeout 20 "$DIR/auth_tool" "$1" "$DIR/audit.log" key words 2>&1 || true; }
printf 'bootstrap admin %s\n' "$PASSWORD" | timeout 20 "$DIR/auth_tool" "$DIR/accounts.json" "$DIR/audit.log" key words >/dev/null
check "store control (600)" "$(store_run "$DIR/accounts.json")" "error the store already holds accounts"
cp accounts.json loose.json
chmod 644 loose.json
check "store mode 644" "$(store_run "$DIR/loose.json")" "account store file rejected"
ln -s accounts.json alias.json
check "store symlink to a 600 file" "$(store_run "$DIR/alias.json")" "account store file rejected"
mkfifo pipe.json
check "store FIFO (no hang)" "$(store_run "$DIR/pipe.json")" "account store file rejected"
cp accounts.json swap.json
check "store before the swap" "$(store_run "$DIR/swap.json")" "error the store already holds accounts"
mv swap.json real.json
ln -s real.json swap.json
check "store after the swap" "$(store_run "$DIR/swap.json")" "account store file rejected"
sudo install -m 600 -o nobody -g nogroup accounts.json other.json
check "store of another user" "$(store_run "$DIR/other.json")" "account store file rejected"

mkdir secrets
printf 'hook-token\n' >secrets/token
printf 'timeout_millis: 2000\nsecret_dirs:\n  acme: %s/secrets\n' "$DIR" >settings.yaml
write_channel() { printf 'name: hook\ntenant: acme\nkind: webhook\ntarget: https://127.0.0.1:9443/x\nsecret_file: %s\n' "$1" >channel.yaml; }
cat >listen.py <<'PY'
import socket
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 9443))
server.listen(1)
server.settimeout(8)
try:
    server.accept()
    open("connected", "w").close()
except socket.timeout:
    pass
PY
send_run() {
    write_channel "$1"
    rm -f connected
    python3 listen.py &
    local listener=$!
    sleep 1
    timeout 30 "$DIR/oncall_send" settings.yaml channel.yaml >/dev/null 2>&1 || true
    wait "$listener" || true
    if [[ -e connected ]]; then printf 'connected'; else printf 'no connection'; fi
}
check "oncall control (600) reads the secret" "$(send_run token)" "connected"
cp secrets/token secrets/loose
chmod 644 secrets/loose
check "oncall mode 644" "$(send_run loose)" "no connection"
ln -s token secrets/alias
check "oncall symlink to a 600 file" "$(send_run alias)" "no connection"
mkfifo secrets/pipe
check "oncall FIFO (no hang)" "$(send_run pipe)" "no connection"
check "oncall name escaping the directory" "$(send_run ../key)" "no connection"
sudo install -m 600 -o nobody -g nogroup secrets/token secrets/other
check "oncall file of another user" "$(send_run other)" "no connection"

link_run() { timeout 20 "$DIR/oncall_link" "$1" 2>&1 | head -n 1 || true; }
head -c 32 /dev/urandom >link.key
check "link key control (600)" "$(link_run "$DIR/link.key" | cut -d: -f1)" "issued length"
cp link.key loose.key
chmod 644 loose.key
check "link key mode 644" "$(link_run "$DIR/loose.key")" "Error: Mode(Mode { file: \"$DIR/loose.key\" })"
ln -s link.key alias.key
check "link key symlink to a 600 file" "$(link_run "$DIR/alias.key")" "Error: Open(Symlink { file: \"$DIR/alias.key\" })"
mkfifo pipe.key
check "link key FIFO (no hang)" "$(link_run "$DIR/pipe.key")" "Error: Open(NotRegular { file: \"$DIR/pipe.key\" })"

printf 'failures: %s\n' "$failures"
exit "$failures"
