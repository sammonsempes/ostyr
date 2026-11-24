#!/usr/bin/env bash
# Usage: deploy/compose/build.sh
# Builds ostyr-platform, auth_tool and web_ui and the container build context under target/deploy-compose/image; then, when Docker is here, the image
# ostyr-platform:local. Without Docker the context is left for a host that has it (the lab copies it).
set -euo pipefail

COMPOSE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$COMPOSE_DIR")")"
OUT_DIR="$REPO_DIR/target/deploy-compose/image"
readonly COMPOSE_DIR REPO_DIR OUT_DIR
export PATH="$HOME/.cargo/bin:$PATH"
cd "$REPO_DIR"

cargo build --release --locked -p platform --bin ostyr-platform -p core-auth --example auth_tool -p web-ui --example web_ui

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/state"
touch "$OUT_DIR/state/.keep"
cp target/release/ostyr-platform target/release/examples/auth_tool target/release/examples/web_ui "$OUT_DIR/"
cp "$COMPOSE_DIR/image/Dockerfile" "$COMPOSE_DIR/image/.dockerignore" "$OUT_DIR/"

if command -v docker >/dev/null; then
    docker build -t ostyr-platform:local "$OUT_DIR"
else
    printf 'docker is not installed here: build the image from %s\n' "$OUT_DIR" >&2
fi
printf '%s\n' "$OUT_DIR"
