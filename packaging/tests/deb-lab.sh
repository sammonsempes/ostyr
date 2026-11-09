#!/usr/bin/env bash
# Usage: packaging/tests/deb-lab.sh <task-id> [<package.deb>]
# Live proof on a booted ubuntu-single lab (lab/up.sh <task-id>): times the one install command (limit 600 s), then reads back the service state,
# the process user, the state directory, the systemd-analyze security score, an authenticated xdrctl whoami and a purge.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$TESTS_DIR")")"
readonly TESTS_DIR REPO_DIR
readonly INSTALL_LIMIT_SECONDS=600
readonly MAX_EXPOSURE="2.5"
readonly ADMIN_PASSWORD="correct-horse-battery-staple"

task_id="${1:?usage: deb-lab.sh <task-id> [<package.deb>]}"
deb="${2:-$REPO_DIR/target/packaging/ostyr-example-module.deb}"
lab_state="$REPO_DIR/lab/state/$task_id"
read -r _ vm_user vm_address <"$lab_state/vms.txt"
failures=0

ssh_options=(-i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

remote() {
    ssh -n "${ssh_options[@]}" "$vm_user@$vm_address" "$@"
}

expect() {
    local description="$1"
    shift
    if "$@"; then
        printf 'ok   %s\n' "$description"
    else
        printf 'FAIL %s\n' "$description"
        failures=$((failures + 1))
    fi
}

scp "${ssh_options[@]}" "$deb" "$vm_user@$vm_address:ostyr-example-module.deb"

started="$(date +%s)"
remote "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./ostyr-example-module.deb" >/dev/null
elapsed=$(($(date +%s) - started))
printf 'info install time %s s\n' "$elapsed"
expect "install takes less than $INSTALL_LIMIT_SECONDS s" test "$elapsed" -lt "$INSTALL_LIMIT_SECONDS"

remote "systemctl status ostyr-example-module --no-pager" || true
expect "the unit is enabled" test "$(remote "systemctl is-enabled ostyr-example-module")" = enabled
expect "the unit is active" test "$(remote "systemctl is-active ostyr-example-module")" = active
expect "the process runs as ostyr-module" test "$(remote "ps -o user= -C ostyr-example-module" | tr -d ' ')" = ostyr-module
expect "the state directory is 0700 owned by ostyr-module" test "$(remote "stat -c '%a %U' /var/lib/ostyr-example-module")" = "700 ostyr-module"
expect "the store key is 0600 owned by ostyr-module" test "$(remote "stat -c '%a %U' /etc/ostyr/example-module/store.key")" = "600 ostyr-module"
printf 'info %s\n' "$(remote "systemd-analyze security ostyr-example-module.service --no-pager | tail -n 1")"
exposure="$(remote "systemd-analyze security ostyr-example-module.service --no-pager | tail -n 1" | sed -n 's/.*exposure level for [^:]*: \([0-9.]*\).*/\1/p')"
expect "exposure level is at most $MAX_EXPOSURE" awk -v level="${exposure:-99}" -v max="$MAX_EXPOSURE" 'BEGIN { exit !(level <= max) }'

expect "GET /health answers over TLS" remote "curl --silent --fail --cacert /etc/ostyr/example-module/ca.crt https://localhost:8443/health"
expect "plain HTTP is not served" bash -c "! ssh -n ${ssh_options[*]} $vm_user@$vm_address 'curl --silent --fail --max-time 5 http://localhost:8443/health'"

bootstrap_output="$(remote "echo \"bootstrap admin $ADMIN_PASSWORD\" | sudo -u ostyr-module ostyr-auth-tool \
    /var/lib/ostyr-example-module/accounts.json /var/lib/ostyr-example-module/audit-cli.log \
    /etc/ostyr/example-module/store.key /etc/ostyr/example-module/compromised.txt")"
secret="$(sed -n 's/^.*secret \([A-Z2-7]*\)$/\1/p' <<<"$bootstrap_output" | head -n 1)"
code="$(remote "echo 'totp $secret' | sudo -u ostyr-module ostyr-auth-tool \
    /var/lib/ostyr-example-module/accounts.json /var/lib/ostyr-example-module/audit-cli.log \
    /etc/ostyr/example-module/store.key /etc/ostyr/example-module/compromised.txt" | sed -n 's/^[^0-9]*\([0-9]\{6\}\)$/\1/p' | head -n 1)"
printf 'info totp code obtained: %s\n' "$([[ -n "$code" ]] && echo yes || echo no)"
xdrctl_base="xdrctl --server https://localhost:8443 --ca-file /etc/ostyr/example-module/ca.crt --config-dir /tmp/xdrctl-proof"
remote "echo '$ADMIN_PASSWORD' | $xdrctl_base login --username admin --totp-code '$code'"
whoami_output="$(remote "$xdrctl_base whoami")"
printf 'info whoami: %s\n' "$whoami_output"
expect "authenticated xdrctl whoami names admin" grep -q admin <<<"$whoami_output"
remote "$xdrctl_base logout" >/dev/null

remote "sudo apt-get purge -y ostyr-example-module" >/dev/null
expect "purge removes the state, the secrets and the user" test "$(remote "test ! -e /var/lib/ostyr-example-module && test ! -e /etc/ostyr/example-module && ! getent passwd ostyr-module && echo gone")" = gone

if [[ "$failures" -ne 0 ]]; then
    printf '%s check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'all checks passed\n'
