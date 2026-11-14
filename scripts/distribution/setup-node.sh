#!/usr/bin/env bash
# One-command Tor-only node layout.
#
# Default: mfnd may open sockets only to localhost, and Tor is the only path
# off the machine. Pass --allow-clearnet HOST:PORT to opt out on purpose.
#
# This script writes units. It does not start a node, open a port, or talk
# to the public testnet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec cargo run --quiet --manifest-path "$ROOT/distribution/node-setup/Cargo.toml" -- "$@"
