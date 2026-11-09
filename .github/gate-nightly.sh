#!/usr/bin/env bash
set -euo pipefail
NIGHTLY_DATE=${1:?usage: gate-nightly.sh YYYY-MM-DD}
HOST=$(rustc -vV | sed -n 's/^host: //p')
rustup toolchain install "nightly-$NIGHTLY_DATE" --profile minimal --component rustfmt --component llvm-tools-preview --no-self-update
ln -sfn "nightly-$NIGHTLY_DATE-$HOST" "${RUSTUP_HOME:-$HOME/.rustup}/toolchains/nightly-$HOST"
cargo +nightly -V
