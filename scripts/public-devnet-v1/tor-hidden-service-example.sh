#!/usr/bin/env bash
# Example Tor hidden-service torrc fragment for mfnd P2P (B8.2).
# Install on VPS; adjust paths and port to match your `--p2p-listen`.
set -euo pipefail

P2P_PORT="${MFND_P2P_LOCAL_PORT:-8333}"
HS_DIR="${TOR_HS_DIR:-/var/lib/tor/permawrite-p2p}"

cat <<EOF
# Permawrite mfnd P2P hidden service (B8.2)
# 1) mfnd serve --p2p-listen 127.0.0.1:${P2P_PORT}
# 2) merge into torrc and reload tor
# 3) cat ${HS_DIR}/hostname -> publish as seed_nodes / MFND_P2P_ONION

HiddenServiceDir ${HS_DIR}
HiddenServicePort ${P2P_PORT} 127.0.0.1:${P2P_PORT}
EOF
