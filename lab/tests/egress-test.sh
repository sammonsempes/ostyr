#!/usr/bin/env bash
# Usage: lab/tests/egress-test.sh
# Boots ubuntu-single and checks the allowlist proxy: apt and docker work, other hosts are refused and logged, nothing else is reachable, and
# the proxy is gone after down.sh. Needs the real host (libvirt, tinyproxy, the ostyr_lab nft table with tcp 3128).
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

readonly TEST_TASK="${LAB_TEST_TASK:-TEGRESS}"
readonly OTHER_TASK="${TEST_TASK}B"
readonly PUBLIC_ADDRESS="1.1.1.1"
readonly PROBE_TIMEOUT_SECONDS=5
readonly REMOTE_TIMEOUT_SECONDS=900

failures=0
check() {
    local description="$1"
    shift
    if "$@"; then
        log "ok   $description"
    else
        log "FAIL $description"
        failures=$((failures + 1))
    fi
}

fails() {
    ! "$@"
}

export LAB_PROFILE="ubuntu-single"
prefix="$(lab_prefix "$TEST_TASK")"
lab_state="$(state_dir "$TEST_TASK")"

cleanup() {
    "$LAB_DIR/down.sh" "$TEST_TASK" >/dev/null 2>&1 || log "cleanup failed"
    "$LAB_DIR/down.sh" "$OTHER_TASK" >/dev/null 2>&1 || log "cleanup of the second lab failed"
}
trap cleanup EXIT

vm() {
    local user address
    read -r _ user address <"$lab_state/vms.txt"
    timeout "$REMOTE_TIMEOUT_SECONDS" ssh -n -i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$user@$address" "$@"
}

proxy_log_has() {
    grep -qF "$1" "$lab_state/proxy/proxy.log"
}

proxy_running() {
    systemctl is-active --quiet "$(proxy_unit "$TEST_TASK")"
}

proxy_runs_unprivileged() {
    [[ "$(ps -o user= -C ostyr-tinyproxy | sort -u)" == "nobody" ]]
}

proxy_log_stays_capped() {
    [[ "$(stat -c %U "$lab_state/proxy/proxy.log")" == "nobody" ]] && [[ "$(systemctl show -p LimitFSIZE --value "$(proxy_unit "$TEST_TASK")")" == "$PROXY_LOG_MAX_BYTES" ]]
}

odd_port_refused() {
    local output
    output="$(vm "curl -sS -o /dev/null -w '%{http_code}' --max-time $PROBE_TIMEOUT_SECONDS http://archive.ubuntu.com:8080/ 2>&1" || true)"
    log "plain http to an allowlisted host on port 8080: $output"
    [[ "$output" == "403" ]]
}

apt_update_clean() {
    local output
    output="$(vm sudo apt-get update 2>&1)"
    log "$output"
    ! grep -q 'Failed to fetch' <<<"$output" && grep -q '^Get:' <<<"$output"
}

docker_pull_works() {
    vm 'command -v docker >/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io >/dev/null; sudo systemctl daemon-reload; sudo systemctl restart docker; sudo docker pull hello-world'
}

refused_with_403() {
    local output
    output="$(vm "curl -sS -o /dev/null -w '%{http_code}' --max-time $PROBE_TIMEOUT_SECONDS http://example.com 2>&1" || true)"
    log "plain http to example.com: $output"
    [[ "$output" == "403" ]]
}

https_refused() {
    local output
    output="$(vm "curl -sS --max-time $PROBE_TIMEOUT_SECONDS https://example.com 2>&1" || true)"
    log "https to example.com: $output"
    grep -q '403' <<<"$output"
}

release_host_allowed() {
    local output
    output="$(vm "curl -sS -o /dev/null -w '%{http_code}' --max-time $PROBE_TIMEOUT_SECONDS https://release-assets.githubusercontent.com/ 2>&1" || true)"
    log "https to release-assets.githubusercontent.com: $output"
    ! grep -q '403' <<<"$output" && ! grep -q 'CONNECT tunnel failed' <<<"$output"
}

neighbour_host_refused() {
    local output
    output="$(vm "curl -sS --max-time $PROBE_TIMEOUT_SECONDS https://evil.githubusercontent.com/ 2>&1" || true)"
    log "https to evil.githubusercontent.com: $output"
    grep -q '403' <<<"$output"
}

direct_fails() {
    vm "sudo ip route replace default via $bridge_address; curl --noproxy '*' -sS --connect-timeout $PROBE_TIMEOUT_SECONDS https://$PUBLIC_ADDRESS"
}

tcp_reaches() {
    vm "nc -zw $PROBE_TIMEOUT_SECONDS $1 $2"
}

"$LAB_DIR/up.sh" "$TEST_TASK"
"$LAB_DIR/up.sh" "$OTHER_TASK"
read -r _ _ vm_address <"$lab_state/vms.txt"
bridge_address="${vm_address%.*}.1"
host_lan_address="$(ip -4 route get "$PUBLIC_ADDRESS" | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
read -r _ _ other_vm_address <"$(state_dir "$OTHER_TASK")/vms.txt"
other_bridge_address="${other_vm_address%.*}.1"

check "proxy process runs" proxy_running
check "proxy listens only on the bridge address" bash -c "ss -ltnH 'sport = :$PROXY_PORT' | awk '{print \$4}' | grep -qx '$bridge_address:$PROXY_PORT' &&
    [[ \"\$(ss -ltnH 'sport = :$PROXY_PORT' | grep -c '$lab_state' || true)\" == 0 ]]"
check "proxy runs as nobody" proxy_runs_unprivileged
check "proxy log is owned by nobody and capped by the unit" proxy_log_stays_capped
check "apt-get update through the proxy" apt_update_clean
check "docker pull through the proxy" docker_pull_works
check "plain http to a host off the allowlist gets 403" refused_with_403
check "plain http to an allowlisted host on another port gets 403" odd_port_refused
check "https to a host off the allowlist is refused" https_refused
check "the GitHub release asset host is allowed" release_host_allowed
check "a neighbouring githubusercontent host is refused" neighbour_host_refused
check "the refusal is logged" proxy_log_has "example.com"
check "direct connection to a public address fails" fails direct_fails
check "host LAN address tcp 22 unreachable" fails tcp_reaches "$host_lan_address" 22
check "host LAN address tcp 3128 unreachable" fails tcp_reaches "$host_lan_address" "$PROXY_PORT"
check "bridge address tcp 22 unreachable" fails tcp_reaches "$bridge_address" 22
check "the second lab proxy listens on its own bridge" bash -c "ss -ltnH 'sport = :$PROXY_PORT' | awk '{print \$4}' | grep -qx '$other_bridge_address:$PROXY_PORT'"
check "another bridge tcp 3128 unreachable" fails tcp_reaches "$other_bridge_address" "$PROXY_PORT"

"$LAB_DIR/down.sh" "$TEST_TASK"
check "no proxy process after down.sh" fails proxy_running
check "nothing listens on the old bridge address" fails bash -c "ss -ltnH | awk '{print \$4}' | grep -qx '$bridge_address:$PROXY_PORT'"
check "state removed" test ! -d "$prefix" -a ! -d "$lab_state"

if ((failures > 0)); then
    die "$failures egress check(s) failed"
fi
log "all egress checks passed"
