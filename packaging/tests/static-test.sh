#!/usr/bin/env bash
# Usage: packaging/tests/static-test.sh
# Static checks of the packaging files on the host: hadolint, systemd-analyze, hardening directives, maintainer scripts. Builds and runs nothing.
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGING_DIR="$(dirname "$TESTS_DIR")"
REPO_DIR="$(dirname "$PACKAGING_DIR")"
readonly TESTS_DIR PACKAGING_DIR REPO_DIR
readonly UNIT="$PACKAGING_DIR/ostyr-example-module.service"
readonly MAX_EXPOSURE="2.5"
export PATH="$HOME/.local/bin:$PATH"

mkdir -p "$REPO_DIR/target"
work="$(mktemp -d "$REPO_DIR/target/packaging-static.XXXXXX")"
trap 'rm -rf "$work"' EXIT
failures=0

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

unit_has() {
    grep -qx -- "$1" "$UNIT"
}

expect "hadolint accepts the Dockerfile" hadolint "$PACKAGING_DIR/Dockerfile"
expect "Dockerfile runs as a numeric non-root user" grep -qx 'USER 65532:65532' "$PACKAGING_DIR/Dockerfile"
expect "Dockerfile uses a distroless base" grep -q '^FROM gcr.io/distroless/' "$PACKAGING_DIR/Dockerfile"

mkdir -p "$work/root/usr/bin" "$work/root/etc/ostyr/example-module"
for stub in ostyr-example-module kill; do
    printf '#!/bin/sh\n' >"$work/root/usr/bin/$stub"
    chmod +x "$work/root/usr/bin/$stub"
done
mkdir -p "$work/root/usr/lib/systemd/system"
for target in sysinit basic network-online multi-user; do
    printf "[Unit]\nDescription=stub\n" >"$work/root/usr/lib/systemd/system/$target.target"
done
cp "$UNIT" "$work/root/usr/lib/systemd/system/"
expect "systemd-analyze verify accepts the unit" systemd-analyze verify --root="$work/root" ostyr-example-module.service

exposure="$(systemd-analyze security --offline=true --root="$work/root" ostyr-example-module.service 2>&1 | sed -n 's/.*Overall exposure level for [^:]*: \([0-9.]*\).*/\1/p')"
printf 'info exposure level %s\n' "$exposure"
expect "exposure level is at most $MAX_EXPOSURE" awk -v level="${exposure:-99}" -v max="$MAX_EXPOSURE" 'BEGIN { exit !(level <= max) }'

for directive in User=ostyr-module Group=ostyr-module NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes PrivateTmp=yes PrivateDevices=yes \
    CapabilityBoundingSet= ProtectKernelTunables=yes ProtectKernelModules=yes ProtectControlGroups=yes RestrictAddressFamilies='AF_INET AF_INET6 AF_UNIX' \
    MemoryDenyWriteExecute=yes LockPersonality=yes RestrictNamespaces=yes StateDirectoryMode=0700 UMask=0077; do
    expect "unit sets $directive" unit_has "$directive"
done
expect "unit grants no writable path beyond the state directory" bash -c "! grep -q '^ReadWritePaths' '$UNIT'"

for script in postinst postrm; do
    expect "$script parses" sh -n "$PACKAGING_DIR/debian/$script"
    expect "shellcheck accepts $script" shellcheck --shell=sh "$PACKAGING_DIR/debian/$script"
done
for script in build.sh tests/static-test.sh tests/postinst-test.sh tests/deb-test.sh tests/image-lab.sh tests/deb-lab.sh; do
    expect "shellcheck accepts $script" shellcheck "$PACKAGING_DIR/$script"
done

expect "module.yaml lists no secret value" bash -c "! grep -qiE 'password|secret:' '$PACKAGING_DIR/module.yaml'"
expect "module.yaml has no comment" bash -c "! grep -q '#' '$PACKAGING_DIR/module.yaml' '$PACKAGING_DIR/module-container.yaml'"

if [[ "$failures" -ne 0 ]]; then
    printf '%s check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'all checks passed\n'
