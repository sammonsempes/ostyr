#!/usr/bin/env bash
# Usage (inside the lab VM, as root): osquery-fetch.sh
# Downloads the osquery .deb of a pinned version through the lab proxy, checks it against the pinned SHA-256 and installs it with dpkg.
# Source of the pin: the osquery release assets page (the digest it shows for osquery_5.24.1-1.linux_amd64.deb); osquery.io/downloads is a client-side
# page that served no digest when this was written, so the same file was also downloaded from pkg.osquery.io and gave the same SHA-256 (two channels).
set -euo pipefail

readonly OSQUERY_VERSION="5.24.1"
readonly OSQUERY_SHA256="c6a37aec1156712cce0fafeb01a3697a2b73a1863a2b39fc3473b07600aea68d"
readonly OSQUERY_URL="https://github.com/osquery/osquery/releases/download/$OSQUERY_VERSION/osquery_$OSQUERY_VERSION-1.linux_amd64.deb"
readonly DOWNLOAD_TIMEOUT_SECONDS=900

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl --fail --location --silent --show-error --max-time "$DOWNLOAD_TIMEOUT_SECONDS" --output "$work/osquery.deb" "$OSQUERY_URL"
actual="$(sha256sum "$work/osquery.deb" | cut -d' ' -f1)"
echo "osquery deb sha256 $actual"
if [[ "$actual" != "$OSQUERY_SHA256" ]]; then
    echo "osquery deb does not match the pinned SHA-256: $actual" >&2
    exit 1
fi
dpkg -i "$work/osquery.deb"
sha256sum /usr/bin/osqueryi
