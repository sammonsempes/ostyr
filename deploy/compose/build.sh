#!/usr/bin/env bash
# Usage: deploy/compose/build.sh
# Builds ostyr-platform, ostyr-auth, ostyr-web-ui, ostyr-playbooks, ostyr-event-gateway, ostyr-relay, ostyr-siem-ingest, ostyr-metrics-ingest and ostyr-metric-alerts and the container build context under target/deploy-compose/image; then, when Docker is here, the image
# ostyr-platform:local. Without Docker the context is left for a host that has it (the lab copies it).
set -euo pipefail

COMPOSE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$COMPOSE_DIR")")"
OUT_DIR="$REPO_DIR/target/deploy-compose/image"
readonly COMPOSE_DIR REPO_DIR OUT_DIR
export PATH="$HOME/.cargo/bin:$PATH"
cd "$REPO_DIR"

cargo build --release --locked -p platform --bin ostyr-platform -p core-auth --bin ostyr-auth -p web-ui --bin ostyr-web-ui -p response-playbooks --bin ostyr-playbooks \
    -p event-gateway --bin ostyr-event-gateway -p relay --bin ostyr-relay -p siem-ingest --bin ostyr-siem-ingest -p metrics-ingest --bin ostyr-metrics-ingest \
    -p metric-alerts --bin ostyr-metric-alerts

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/state"
touch "$OUT_DIR/state/.keep"
mkdir -p "$OUT_DIR/playbooks-state"
touch "$OUT_DIR/playbooks-state/.keep"
mkdir -p "$OUT_DIR/gateway-state/commands"
touch "$OUT_DIR/gateway-state/commands/.keep"
mkdir -p "$OUT_DIR/relay-state"
touch "$OUT_DIR/relay-state/.keep"
for state_dir in siem-state metrics-state metric-alerts-state; do
    mkdir -p "$OUT_DIR/$state_dir"
    touch "$OUT_DIR/$state_dir/.keep"
done
cp target/release/ostyr-platform target/release/ostyr-auth target/release/ostyr-web-ui target/release/ostyr-playbooks target/release/ostyr-event-gateway target/release/ostyr-relay target/release/ostyr-siem-ingest target/release/ostyr-metrics-ingest target/release/ostyr-metric-alerts "$OUT_DIR/"
cp "$COMPOSE_DIR/image/Dockerfile" "$COMPOSE_DIR/image/.dockerignore" "$OUT_DIR/"

if command -v docker >/dev/null; then
    docker build -t ostyr-platform:local "$OUT_DIR"
else
    printf 'docker is not installed here: build the image from %s\n' "$OUT_DIR" >&2
fi
printf '%s\n' "$OUT_DIR"
