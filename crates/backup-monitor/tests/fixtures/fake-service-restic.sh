#!/bin/sh
dir=$(dirname "$0")
echo "$@" >> "$dir/args"
verb=
for argument; do
  case "$argument" in
  config) verb=config ;;
  dump) verb=dump ;;
  list) verb=list ;;
  snapshots) if [ "$verb" != list ]; then verb=snapshots; fi ;;
  esac
done
if [ -e "$dir/block" ] && [ "$(cat "$dir/block")" = "$verb" ]; then
  touch "$dir/blocked"
  i=0
  while [ ! -e "$dir/release" ] && [ "$i" -lt 600 ]; do
    sleep 0.1
    i=$((i + 1))
  done
fi
if [ -e "$dir/delay" ]; then sleep "$(cat "$dir/delay")"; fi
if [ -e "$dir/fail_$verb" ]; then exit 1; fi
case "$verb" in
dump) cat "$dir/canary" ;;
list) cat "$dir/list.txt" ;;
*) cat "$dir/$verb.json" ;;
esac
