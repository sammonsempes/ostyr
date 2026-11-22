#!/bin/sh
if [ "$*" = "-json -silent -duc -rate 100 -p 22 -host 8.8.8.8/32" ]; then
    printf '%s\n' '{"ip":"8.8.8.8","port":22}'
else
    exit 7
fi
