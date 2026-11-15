#!/usr/bin/env bash
# Usage (inside the lab VM, as root): fetch-yr.sh
# Downloads the YARA-X release tarball through the lab proxy, checks it against the pinned SHA-256 (the digest the release page publishes for the asset)
# and installs `yr` as /usr/local/bin/yr (root-owned, mode 0755).
set -euo pipefail

readonly YARA_X_VERSION="v1.23.0"
readonly YARA_X_SHA256="da0c17f23fc743dcd44ad6d3135c906a4c0d197685b661c4cdc923c2f8967a64"
readonly YARA_X_URL="https://github.com/VirusTotal/yara-x/releases/download/$YARA_X_VERSION/yara-x-$YARA_X_VERSION-x86_64-unknown-linux-gnu.tar.gz"
readonly DOWNLOAD_TIMEOUT_SECONDS=600

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl --fail --location --silent --show-error --max-time "$DOWNLOAD_TIMEOUT_SECONDS" --output "$work/yara-x.tar.gz" "$YARA_X_URL"
actual="$(sha256sum "$work/yara-x.tar.gz" | cut -d' ' -f1)"
if [[ "$actual" != "$YARA_X_SHA256" ]]; then
    echo "yara-x tarball does not match the pinned SHA-256: $actual" >&2
    exit 1
fi
mkdir "$work/out"
tar -xzf "$work/yara-x.tar.gz" -C "$work/out"
install -o root -g root -m 0755 "$work/out/yr" /usr/local/bin/yr
sha256sum /usr/local/bin/yr
