#!/usr/bin/env bash
# Shared VPS bind helpers (Lane 7 / TL-4+).
set -euo pipefail

vps_export_binds() {
  local role="$1"
  unset MFN_RPC_LISTEN MFN_P2P_LISTEN
  case "$role" in
    hub)
      [[ -n "${MFN_RPC_LISTEN_HUB:-}" ]] && export MFN_RPC_LISTEN="$MFN_RPC_LISTEN_HUB"
      [[ -n "${MFN_P2P_LISTEN_HUB:-}" ]] && export MFN_P2P_LISTEN="$MFN_P2P_LISTEN_HUB"
      ;;
    v1)
      [[ -n "${MFN_RPC_LISTEN_V1:-}" ]] && export MFN_RPC_LISTEN="$MFN_RPC_LISTEN_V1"
      [[ -n "${MFN_P2P_LISTEN_V1:-}" ]] && export MFN_P2P_LISTEN="$MFN_P2P_LISTEN_V1"
      ;;
    v2)
      [[ -n "${MFN_RPC_LISTEN_V2:-}" ]] && export MFN_RPC_LISTEN="$MFN_RPC_LISTEN_V2"
      [[ -n "${MFN_P2P_LISTEN_V2:-}" ]] && export MFN_P2P_LISTEN="$MFN_P2P_LISTEN_V2"
      ;;
    observer)
      [[ -n "${MFN_RPC_LISTEN_OBSERVER:-}" ]] && export MFN_RPC_LISTEN="$MFN_RPC_LISTEN_OBSERVER"
      [[ -n "${MFN_P2P_LISTEN_OBSERVER:-}" ]] && export MFN_P2P_LISTEN="$MFN_P2P_LISTEN_OBSERVER"
      ;;
  esac
}

load_vps_bind_file() {
  local script_dir="$1"
  local bind="${MFN_VPS_BIND_FILE:-$script_dir/vps-bind.env}"
  if [[ ! -f "$bind" ]]; then
    echo "vps-bind: missing $bind (copy vps-bind.env.example)" >&2
    return 1
  fi
  # shellcheck source=/dev/null
  source "$bind"
  echo "vps-bind: loaded $bind"
  return 0
}

vps_assert_public_p2p_binds() {
  local role bind_var listen
  for role in HUB V1 V2 OBSERVER; do
    bind_var="MFN_P2P_LISTEN_${role}"
    listen="${!bind_var:-}"
    if [[ -z "$listen" ]]; then
      echo "vps-preflight: WARN missing $bind_var" >&2
      continue
    fi
    if [[ "$listen" != 0.0.0.0:* && "$listen" != "[::]:"* ]]; then
      echo "vps-preflight: FAIL $bind_var=$listen must bind public P2P (0.0.0.0:PORT)" >&2
      return 1
    fi
  done
  return 0
}

vps_assert_loopback_rpc_binds() {
  local role bind_var listen host
  for role in HUB V1 V2 OBSERVER; do
    bind_var="MFN_RPC_LISTEN_${role}"
    listen="${!bind_var:-}"
    if [[ -z "$listen" ]]; then
      continue
    fi
    host="${listen%%:*}"
    if [[ "$host" != "127.0.0.1" ]]; then
      echo "vps-preflight: FAIL $bind_var=$listen RPC must stay loopback-only (127.0.0.1)" >&2
      return 1
    fi
  done
  return 0
}
