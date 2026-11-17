#!/bin/sh
printf '%s\n' 'STDERR-MARKER-secret-text' >&2
printf '%s\n' '{"ip":"8.8.8.8","port":22}'
exit 1
