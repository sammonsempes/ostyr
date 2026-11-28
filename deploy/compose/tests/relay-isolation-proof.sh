#!/usr/bin/env bash
# Usage: sudo bash -s -- <nats-box image> < relay-isolation-proof.sh
# Runs inside the lab VM, in the compose directory, with the stack up. The relay image is distroless, so every probe runs in a nats-box container that
# joins the relay container's network namespace (same interfaces, routes and source address as the relay). Prints `key value` lines.
set -euo pipefail

probe_image="${1:?usage: relay-isolation-proof.sh <nats-box image>}"
readonly probe_image
readonly CONNECT_SECONDS=3
readonly DRIP_CONNECTIONS=200
readonly DRIP_SECONDS=20
readonly DRIP_SETTLE_SECONDS=8

container_of() {
    docker compose ps -q "$1"
}

address_in() {
    docker inspect --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$(container_of "$1")"
}

network_gateway() {
    docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "$1"
}

relay_container="$(container_of relay)"
readonly relay_container

in_relay() {
    docker run --rm --network "container:$relay_container" "$probe_image" "$@"
}

connect_result() {
    if in_relay nc -z -w "$CONNECT_SECONDS" "$1" "$2" >/dev/null 2>&1; then
        printf 'reachable'
    else
        printf 'unreachable'
    fi
}

report_connect() {
    printf 'connect %s %s:%s %s\n' "$1" "$2" "$3" "$(connect_result "$2" "$3")"
}

printf 'host_listeners\n'
ss -ltnH | awk '{print "  " $4}' | sort
printf 'relay_networks %s\n' "$(docker inspect --format '{{range $name, $net := .NetworkSettings.Networks}}{{$name}} {{end}}' "$relay_container")"
printf 'relay_routes\n'
in_relay ip route | sed 's/^/  /'
printf 'gateway_relay_net_address %s\n' "$(address_in gateway ostyr_relay_net)"
printf 'gateway_ip_forward %s\n' "$(nsenter -t "$(docker inspect --format '{{.State.Pid}}' "$(container_of gateway)")" -n cat /proc/sys/net/ipv4/ip_forward)"
report_connect clickhouse "$(address_in clickhouse ostyr_default)" 8443
report_connect postgres "$(address_in postgres ostyr_default)" 5432
report_connect nats "$(address_in nats ostyr_default)" 4222
report_connect platform "$(address_in platform ostyr_default)" 8443
report_connect gateway_default_ip "$(address_in gateway ostyr_default)" 7443
report_connect gateway_default_ip "$(address_in gateway ostyr_default)" 4222
for gateway_ip in "$(network_gateway ostyr_relay_net)" "$(network_gateway ostyr_relay_edge)" "$(network_gateway ostyr_default)"; do
    for port in 5432 4222 8443 7443; do
        report_connect bridge_gateway "$gateway_ip" "$port"
    done
done
for host_ip in $(hostname -I); do
    for port in 5432 4222 8443 9443 7443; do
        report_connect host_address "$host_ip" "$port"
    done
done
report_connect gateway_relay_listener "$(address_in gateway ostyr_relay_net)" 7443
report_connect gateway_relay_net_ports "$(address_in gateway ostyr_relay_net)" 4222
printf 'metadata_endpoint %s\n' "$(connect_result 169.254.169.254 80)"

gateway_rss() {
    awk '/^VmRSS/ {print $2}' "/proc/$(docker inspect --format '{{.State.Pid}}' "$(container_of gateway)")/status"
}

drip() {
    in_relay sh -c "i=0; while [ \$i -lt $DRIP_CONNECTIONS ]; do (sleep $DRIP_SECONDS | nc -w $DRIP_SECONDS $1 $2 >/dev/null 2>&1 &); i=\$((i + 1)); done; sleep $DRIP_SETTLE_SECONDS; netstat -tn | grep -c ':$2 '" 2>&1
}

printf 'gateway_rss_before_kb %s\n' "$(gateway_rss)"
printf 'drip_gateway_relay_listener_open %s\n' "$(drip "$(address_in gateway ostyr_relay_net)" 7443)"
printf 'gateway_rss_after_kb %s\n' "$(gateway_rss)"
printf 'drip_platform_through_edge_open %s\n' "$(drip "$(network_gateway ostyr_relay_edge)" 8443)"
printf 'platform_health_after_drip %s\n' "$(curl --silent --max-time 20 --cacert secrets/ca.crt https://localhost:8443/health 2>&1 | head -c 100)"
