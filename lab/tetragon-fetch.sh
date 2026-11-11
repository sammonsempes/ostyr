#!/usr/bin/env bash
# Usage: lab/tetragon-fetch.sh
# Downloads the Tetragon release tarball into ~/.cache/ostyr-lab/tetragon (override LAB_TETRAGON_CACHE), checks it against the pinned SHA-256 (also the
# digest GitHub shows for the asset and the content of the published .sha256sum file) and prints its path. A cached file is re-checked every time and a
# mismatch deletes it and fails.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

readonly TETRAGON_VERSION="v1.8.0"
readonly TETRAGON_SHA256="e88691c5f05a2a61aba58974a080603050b924c7f13ecc06f3d05172feb05f59"
readonly TETRAGON_URL="https://github.com/cilium/tetragon/releases/download/$TETRAGON_VERSION/tetragon-$TETRAGON_VERSION-amd64.tar.gz"
readonly DOWNLOAD_TIMEOUT_SECONDS=900

cache_dir="${LAB_TETRAGON_CACHE:-$HOME/.cache/ostyr-lab/tetragon}"
tarball="$cache_dir/tetragon-$TETRAGON_VERSION-amd64.tar.gz"
mkdir -p "$cache_dir"

digest_of() {
    sha256sum "$1" | cut -d' ' -f1
}

if [[ -f "$tarball" && "$(digest_of "$tarball")" != "$TETRAGON_SHA256" ]]; then
    log "cached Tetragon tarball does not match the pin, deleting it"
    rm -f "$tarball"
fi
if [[ ! -f "$tarball" ]]; then
    partial="$(mktemp "$cache_dir/download.XXXXXX")"
    curl --fail --location --silent --show-error --max-time "$DOWNLOAD_TIMEOUT_SECONDS" --output "$partial" "$TETRAGON_URL"
    if [[ "$(digest_of "$partial")" != "$TETRAGON_SHA256" ]]; then
        rm -f "$partial"
        die "Tetragon tarball does not match the pinned SHA-256"
    fi
    mv "$partial" "$tarball"
fi
printf '%s\n' "$tarball"
