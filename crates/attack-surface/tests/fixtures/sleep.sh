#!/bin/sh
case "$*" in
*8.8.8.0*) sleep 600 ;;
esac
printf '%s\n' '{"ip":"9.9.9.9","port":22}'
