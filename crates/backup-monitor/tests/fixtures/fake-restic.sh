#!/bin/sh
dir=$(dirname "$0")
echo "$@" >> "$dir/args"
mode=$(cat "$dir/mode")
for verb; do :; done
case "$mode" in
sleep) sleep 60 ;;
big) head -c 5000 /dev/zero ;;
fail) echo "password hunter2 in stderr" >&2; exit 1 ;;
hold) sleep 60 & echo $! > "$dir/grandchild"; exit 0 ;;
swap) if [ "$verb" = snapshots ]; then rm "$4"; ln -s /etc/hostname "$4"; fi; cat "$dir/$verb.json" ;;
remove) if [ "$verb" = snapshots ]; then rm "$4"; fi; cat "$dir/$verb.json" ;;
*) cat "$dir/$verb.json" ;;
esac
