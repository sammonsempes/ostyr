#!/bin/sh
dir=$(dirname "$0")
echo "$@" >> "$dir/args"
env | sort > "$dir/env"
cat > "$dir/stdin"
if [ -e "$BORG_BASE_DIR/marker" ]; then echo seen >> "$dir/seen"; fi
touch "$BORG_BASE_DIR/marker"
mode=$(cat "$dir/mode")
case "$mode" in
sleep) sleep 60 ;;
big) head -c 5000 /dev/zero ;;
fail) echo "passphrase hunter2 in stderr" >&2; exit 2 ;;
warn) cat "$dir/list.json"; exit 1 ;;
hold) sleep 60 & echo $! > "$dir/grandchild"; exit 0 ;;
*) cat "$dir/list.json" ;;
esac
