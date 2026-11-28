#!/bin/sh
dir=$(dirname "$0")
echo "$@" >> "$dir/args"
mode=$(cat "$dir/mode")
last=
for argument; do last=$argument; done
if [ "$last" = config ] && [ -e "$dir/config.fail" ]; then exit 1; fi
verb=
for argument; do
  if [ "$argument" = dump ]; then verb=dump; fi
  if [ "$argument" = list ]; then verb=list; fi
done
if [ "$verb" = list ]; then
  case "$(cat "$dir/list_mode" 2>/dev/null)" in
  hang) sleep 60 ;;
  fail) exit 1 ;;
  *) cat "$dir/list.txt" ;;
  esac
elif [ "$verb" != dump ]; then
  for verb; do :; done
  cat "$dir/$verb.json"
else
  case "$mode" in
  big) head -c 5000 /dev/zero ;;
  failed) cat "$dir/canary"; echo "/secret/path $(printf '\033[31m') hunter2" >&2; exit 1 ;;
  sleep) sleep 60 ;;
  hold) sleep 3600 & echo $! > "$dir/grandchild"; head -c 5000 /dev/zero; exit 0 ;;
  swap) rm "$4"; ln -s /etc/hostname "$4"; cat "$dir/canary" ;;
  *) cat "$dir/canary" ;;
  esac
fi
