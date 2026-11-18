#!/usr/bin/env bash
set -euo pipefail

# working dir inside container
cd /usr/src/app

BIN=target/x86_64-unknown-linux-musl/release/OpenNeutron

# Rebuild when the sources are newer than the binary, not merely when the binary is absent.
#
# This used to be `if [ ! -x "$BIN" ]`, and the image carries the host's target/ directory,
# so a freshly built image would happily start a binary compiled days earlier. A deploy then
# reports success while serving old code — which is exactly how a working endpoint appeared
# to 404 four times in a row. A stale binary that looks healthy is the worst kind of deploy.
needs_build() {
  [ ! -x "$BIN" ] && return 0
  # Any source, manifest or build script newer than the binary means rebuild.
  local newer
  newer=$(find src Cargo.toml Cargo.lock build.rs -newer "$BIN" -print -quit 2>/dev/null || true)
  [ -n "$newer" ]
}

if needs_build; then
  echo "Building for x86_64-unknown-linux-musl (sources newer than binary, or no binary)..."
  cargo build --release --target x86_64-unknown-linux-musl
else
  echo "Binary is newer than every source, skipping build."
fi

# Always run the app with local config file (mounted or default)
exec "$BIN"
