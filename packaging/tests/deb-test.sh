#!/usr/bin/env bash
# Usage: packaging/tests/deb-test.sh <package.deb>
# Checks the built package: metadata, file list and modes, the unit and the SBOMs it ships (CycloneDX 1.5 JSON with components).
set -euo pipefail

deb="${1:?usage: deb-test.sh <package.deb>}"
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$TESTS_DIR")")"
readonly TESTS_DIR REPO_DIR

mkdir -p "$REPO_DIR/target"
work="$(mktemp -d "$REPO_DIR/target/packaging-deb.XXXXXX")"
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

listing="$(dpkg-deb -c "$deb")"
has_entry() {
    grep -qE "$1" <<<"$listing"
}

dpkg-deb -x "$deb" "$work/root"
dpkg-deb -e "$deb" "$work/control"

expect "package name" test "$(dpkg-deb -f "$deb" Package)" = ostyr-example-module
expect "architecture" test "$(dpkg-deb -f "$deb" Architecture)" = amd64
expect "depends on openssl and adduser" bash -c "dpkg-deb -f '$deb' Depends | grep -q openssl && dpkg-deb -f '$deb' Depends | grep -q adduser"
expect "binaries are executable and root-owned" has_entry '^-rwxr-xr-x 0/0 +[0-9]+ .* \./usr/bin/ostyr-example-module$'
expect "the unit is installed" has_entry '^-rw-r--r-- 0/0 +[0-9]+ .* \./usr/lib/systemd/system/ostyr-example-module\.service$'
expect "the configuration is a conffile" grep -qx '/etc/ostyr/example-module/module.yaml' "$work/control/conffiles"
expect "nothing is world-writable" bash -c "! find '$work/root' -perm -o+w | grep -q ."
expect "maintainer scripts are executable" test -x "$work/control/postinst" -a -x "$work/control/postrm"
expect "postinst enables the unit" grep -q 'deb-systemd-helper' "$work/control/postinst"
expect "postinst keeps the state directory 0700" grep -q 'chmod 0700' "$work/control/postinst"
expect "the installed unit equals the source unit" cmp -s "$work/root/usr/lib/systemd/system/ostyr-example-module.service" "$REPO_DIR/packaging/ostyr-example-module.service"

for sbom in core-api core-auth xdrctl; do
    file="$work/root/usr/share/doc/ostyr-example-module/sbom/$sbom.cdx.json"
    expect "SBOM $sbom is CycloneDX 1.5" test "$(jq -r '"\(.bomFormat) \(.specVersion)"' "$file")" = "CycloneDX 1.5"
    expect "SBOM $sbom lists components" test "$(jq '.components | length' "$file")" -gt 0
done

if [[ "$failures" -ne 0 ]]; then
    printf '%s check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'all checks passed\n'
