#!/usr/bin/env bash
# Usage: packaging/build.sh
# Builds the example module release binaries, the CycloneDX SBOMs, the .deb and the container build context under target/packaging/.
set -euo pipefail

PACKAGING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$PACKAGING_DIR")"
OUT_DIR="$REPO_DIR/target/packaging"
readonly PACKAGING_DIR REPO_DIR OUT_DIR
export PATH="$HOME/.cargo/bin:$PATH"
cd "$REPO_DIR"

for tool in cargo-deb cargo-cyclonedx; do
    if ! command -v "$tool" >/dev/null; then
        printf 'error: %s is not installed (cargo install %s --locked)\n' "$tool" "$tool" >&2
        exit 1
    fi
done

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/image"

cargo build --release --locked -p core-api --example module_api -p core-auth --example auth_tool -p xdrctl --example xdrctl

mkdir -p target/release/sbom
cargo cyclonedx --format json --spec-version 1.5 --override-filename sbom.cdx
for crate in core-api core-auth xdrctl; do
    mv "crates/$crate/sbom.cdx.json" "target/release/sbom/$crate.cdx.json"
done
find crates tools -name sbom.cdx.json -delete

cargo deb --no-build -p core-api --output "$OUT_DIR/ostyr-example-module.deb"

cp target/release/examples/module_api "$OUT_DIR/image/ostyr-example-module"
cp "$PACKAGING_DIR/Dockerfile" "$PACKAGING_DIR/.dockerignore" "$OUT_DIR/image/"
cp "$PACKAGING_DIR/module-container.yaml" "$PACKAGING_DIR/compromised.txt" "$OUT_DIR/image/"
printf '%s\n' "$OUT_DIR"
