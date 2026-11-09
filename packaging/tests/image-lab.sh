#!/usr/bin/env bash
# Usage: packaging/tests/image-lab.sh <task-id>
# Builds and runs the container image inside a booted ubuntu-single lab (lab/up.sh <task-id>), never on the host: Docker comes from the Ubuntu package
# through the lab proxy, the base image from gcr.io through the proxy. Needs target/packaging/image from packaging/build.sh.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$TESTS_DIR")")"
readonly TESTS_DIR REPO_DIR
readonly IMAGE_DIR="$REPO_DIR/target/packaging/image"
readonly READY_ATTEMPTS=20

task_id="${1:?usage: image-lab.sh <task-id>}"
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

remote "rm -rf image && mkdir image"
scp -r "${ssh_options[@]}" "$IMAGE_DIR/." "$vm_user@$vm_address:image/"

remote "command -v docker >/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io openssl" >/dev/null
remote "cd image && sudo docker build -t ostyr-example-module:lab ."

remote "sudo rm -rf conf state && mkdir conf state && cp image/module-container.yaml conf/module.yaml && cp image/compromised.txt conf/ \
    && head -c 32 /dev/urandom >conf/store.key \
    && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj /CN=localhost \
        -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout conf/tls.key -out conf/tls.crt 2>/dev/null \
    && sudo chown -R 65532:65532 conf state && sudo chmod 0600 conf/store.key conf/tls.key && sudo chmod 0700 state"
remote "sudo docker rm -f ostyr-module >/dev/null 2>&1; sudo docker run -d --name ostyr-module --read-only --cap-drop ALL --security-opt no-new-privileges \
    -p 8443:8443 -v \$PWD/conf:/etc/ostyr:ro -v \$PWD/state:/var/lib/ostyr ostyr-example-module:lab /etc/ostyr/module.yaml" >/dev/null

ready() {
    remote "for attempt in \$(seq 1 $READY_ATTEMPTS); do curl --silent --fail --cacert conf/tls.crt https://localhost:8443/health && exit 0; sleep 1; done; exit 1"
}

remote "sudo docker ps --filter name=ostyr-module --format '{{.Status}}'"
expect "the module answers /health over TLS from the container" ready
expect "the image runs as user 65532" test "$(remote "sudo docker inspect --format '{{.Config.User}}' ostyr-example-module:lab")" = 65532:65532
expect "the root filesystem is read-only" test "$(remote "sudo docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' ostyr-module")" = true
expect "the container process runs as uid 65532" test "$(remote "ps -o uid= -p \$(sudo docker inspect --format '{{.State.Pid}}' ostyr-module)" | tr -d ' ')" = 65532
printf 'info image size: %s\n' "$(remote "sudo docker image inspect --format '{{.Size}}' ostyr-example-module:lab")"
remote "sudo docker rm -f ostyr-module" >/dev/null

if [[ "$failures" -ne 0 ]]; then
    printf '%s check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'all checks passed\n'
