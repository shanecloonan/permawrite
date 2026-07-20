#!/usr/bin/env bash
# Pick free loopback P2P listen addrs in the B-71 persistable band (<32768).
# shellcheck shell=bash

# Linux ephemeral floor used by mfn_store::MIN_EPHEMERAL_PEER_PORT.
MFN_PERSISTABLE_P2P_PORT_LO="${MFN_PERSISTABLE_P2P_PORT_LO:-19000}"
MFN_PERSISTABLE_P2P_PORT_HI="${MFN_PERSISTABLE_P2P_PORT_HI:-32767}"

# Print HOST:PORT on stdout. Host defaults to 127.0.0.1.
pick_persistable_p2p_listen() {
  local host="${1:-127.0.0.1}"
  local lo="$MFN_PERSISTABLE_P2P_PORT_LO"
  local hi="$MFN_PERSISTABLE_P2P_PORT_HI"
  local span=$((hi - lo + 1))
  local start=$((lo + (RANDOM % span)))
  local i port
  for i in $(seq 0 $((span - 1))); do
    port=$((lo + ((start - lo + i) % span)))
    if command -v python3 >/dev/null 2>&1; then
      if python3 - "$host" "$port" <<'PY' 2>/dev/null
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind((host, port))
except OSError:
    sys.exit(1)
s.close()
sys.exit(0)
PY
      then
        printf '%s:%s\n' "$host" "$port"
        return 0
      fi
    elif (echo >/dev/tcp/"$host"/"$port") >/dev/null 2>&1; then
      # Port appears open (in use) — skip.
      continue
    else
      # Best-effort when python3 missing: assume free if connect fails.
      printf '%s:%s\n' "$host" "$port"
      return 0
    fi
  done
  echo "pick_persistable_p2p_listen: no free port in ${lo}..${hi}" >&2
  return 1
}
