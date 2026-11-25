#!/usr/bin/env bash
# Usage: ADMIN_PASSWORD=.. GATEWAY_PASSWORD=.. SIEM_PASSWORD=.. METRICS_PASSWORD=.. mark-nats-passwords.sh < nats.conf
# Prints the configuration with each of the four passwords replaced by its marker, so it can be compared with the golden file.
set -euo pipefail
conf="$(cat)"
conf="${conf//"${ADMIN_PASSWORD:?}"/adminpw}"
conf="${conf//"${GATEWAY_PASSWORD:?}"/gatewaypw}"
conf="${conf//"${SIEM_PASSWORD:?}"/siempw}"
conf="${conf//"${METRICS_PASSWORD:?}"/metricspw}"
printf '%s\n' "$conf"
