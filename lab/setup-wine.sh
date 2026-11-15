#!/usr/bin/env bash
# Usage: sudo lab/setup-wine.sh
# Installs Wine (wine64) from the distribution archive and creates the Wine prefix under target/wine-prefix. Idempotent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly PREFIX="${WINEPREFIX:-$ROOT/target/wine-prefix}"
readonly INIT_TIMEOUT_SECONDS=300
export WINEDEBUG=-all
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

if ! command -v wine64 >/dev/null; then
    if [ "$(id -u)" -ne 0 ]; then
        echo "setup-wine.sh: run as root to install wine64" >&2
        exit 1
    fi
    removed="$(apt-get -s install -y --no-install-recommends wine64 | grep -c '^Remv' || true)"
    if [ "$removed" -ne 0 ]; then
        echo "setup-wine.sh: apt would remove $removed packages, refusing" >&2
        exit 1
    fi
    apt-get install -y --no-install-recommends wine64
fi

mkdir -p "$PREFIX"
export WINEPREFIX="$PREFIX"
timeout "$INIT_TIMEOUT_SECONDS" wine64 wineboot --init >/dev/null 2>&1
wine64 --version
echo "setup-wine.sh: prefix $PREFIX ready"
