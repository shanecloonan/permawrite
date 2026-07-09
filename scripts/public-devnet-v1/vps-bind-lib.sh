#!/usr/bin/env bash
# Shared VPS bind helpers (Lane 7 / TL-4+).
set -euo pipefail

vps_export_binds() {
  local role="$1"
  unset MFN_RPC_LISTEN MFN_P2P_LISTEN
  # Use if/fi — `[[ -n ... ]] && export` aborts callers with `set -e` when VPS binds are unset.
  case "$role" in
    hub)
      if [[ -n "${MFN_RPC_LISTEN_HUB:-}" ]]; then
        export MFN_RPC_LISTEN="$MFN_RPC_LISTEN_HUB"
      fi
      if [[ -n "${MFN_P2P_LISTEN_HUB:-}" ]]; then
        export MFN_P2P_LISTEN="$MFN_P2P_LISTEN_HUB"
      fi
      ;;
    v1)
      if [[ -n "${MFN_RPC_LISTEN_V1:-}" ]]; then
        export MFN_RPC_LISTEN="$MFN_RPC_LISTEN_V1"
      fi
      if [[ -n "${MFN_P2P_LISTEN_V1:-}" ]]; then
        export MFN_P2P_LISTEN="$MFN_P2P_LISTEN_V1"
      fi
      ;;
    v2)
      if [[ -n "${MFN_RPC_LISTEN_V2:-}" ]]; then
        export MFN_RPC_LISTEN="$MFN_RPC_LISTEN_V2"
      fi
      if [[ -n "${MFN_P2P_LISTEN_V2:-}" ]]; then
        export MFN_P2P_LISTEN="$MFN_P2P_LISTEN_V2"
      fi
      ;;
    observer)
      if [[ -n "${MFN_RPC_LISTEN_OBSERVER:-}" ]]; then
        export MFN_RPC_LISTEN="$MFN_RPC_LISTEN_OBSERVER"
      fi
      if [[ -n "${MFN_P2P_LISTEN_OBSERVER:-}" ]]; then
        export MFN_P2P_LISTEN="$MFN_P2P_LISTEN_OBSERVER"
      fi
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

# Public devnet genesis + MFER policy (B1 phase 2d) — VPS must match local RC rehearsal chain.
vps_assert_public_devnet_policy() {
  local repo_root="$1"
  local manifest="$repo_root/mfn-node/testdata/public_devnet_v1.manifest.json"
  local spec="$repo_root/mfn-node/testdata/public_devnet_v1.json"
  local expected_genesis="454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005"
  if [[ ! -f "$manifest" || ! -f "$spec" ]]; then
    echo "vps-preflight: FAIL missing public devnet manifest or genesis spec" >&2
    return 1
  fi
  MFN_VPS_MANIFEST="$manifest" MFN_VPS_SPEC="$spec" MFN_VPS_EXPECTED_GENESIS="$expected_genesis" python3 - <<'PY'
import json, os, sys

manifest = json.load(open(os.environ["MFN_VPS_MANIFEST"]))
spec = json.load(open(os.environ["MFN_VPS_SPEC"]))
expected = os.environ["MFN_VPS_EXPECTED_GENESIS"]
genesis_id = manifest.get("genesis_id", "")
if genesis_id != expected:
    print(
        f"vps-preflight: FAIL genesis_id={genesis_id} expected {expected}",
        file=sys.stderr,
    )
    sys.exit(1)
mfer = int(spec.get("endowment", {}).get("require_endowment_range_proof", 0))
if mfer != 1:
    print(
        "vps-preflight: FAIL require_endowment_range_proof="
        f"{mfer} (public devnet requires MFER=1 for TL-5/TL-6)",
        file=sys.stderr,
    )
    sys.exit(1)
print("vps-preflight: OK public_devnet_v1 policy genesis_id match + MFER required")
PY
}
