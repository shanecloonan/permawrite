#!/usr/bin/env bash
# Shared public-devnet port file and soak-lock helpers (bash parity with ports-env-lib.ps1).
set -euo pipefail

soak_lock_path() {
  local script_dir="${1:?script_dir required}"
  echo "$script_dir/.soak-active.lock"
}

soak_lock_active() {
  local script_dir="$1"
  local lock_path pid line
  lock_path="$(soak_lock_path "$script_dir")"
  if [[ ! -f "$lock_path" ]]; then
    return 1
  fi
  while IFS= read -r line; do
    if [[ "$line" =~ ^pid=([0-9]+)$ ]]; then
      pid="${BASH_REMATCH[1]}"
      if kill -0 "$pid" 2>/dev/null; then
        return 0
      fi
    fi
  done <"$lock_path"
  return 1
}

assert_soak_not_active() {
  local script_dir="$1" caller="$2"
  if [[ "${MFN_SOAK_BOOTSTRAP:-}" == "1" ]]; then
    return 0
  fi
  if soak_lock_active "$script_dir"; then
    echo "${caller}: soak in progress ($(soak_lock_path "$script_dir")); wait for soak to finish or remove stale lock if no soak is running" >&2
    exit 1
  fi
}

soak_lock_new() {
  local script_dir="$1"
  local lock_path stamp
  lock_path="$(soak_lock_path "$script_dir")"
  stamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf 'pid=%s\nstarted_at=%s\n' "$$" "$stamp" >"$lock_path"
}

soak_lock_remove() {
  local script_dir="$1"
  local lock_path
  lock_path="$(soak_lock_path "$script_dir")"
  rm -f "$lock_path"
}

# Resolve release mfn-cli for hub tip polls (M2.5.9).
resolve_mfn_cli() {
  local repo_root="${1:?repo_root required}"
  local bin="$repo_root/target/release/mfn-cli"
  if [[ ! -x "$bin" ]]; then
    bin="$repo_root/target/release/mfn-cli.exe"
  fi
  if [[ ! -x "$bin" ]]; then
    return 1
  fi
  printf '%s\n' "$bin"
}

# Query hub tip height via mfn-cli, falling back to get_status JSON-RPC (M2.5.9).
query_tip_height() {
  local rpc_addr="$1"
  local repo_root="${2:-}"
  local mfn_cli tip_out tip_height host port line req
  if [[ -n "$repo_root" ]]; then
    mfn_cli="$(resolve_mfn_cli "$repo_root" 2>/dev/null || true)"
  fi
  if [[ -n "${mfn_cli:-}" ]]; then
    if tip_out="$("$mfn_cli" --rpc "$rpc_addr" tip 2>/dev/null)"; then
      tip_height="$(awk '{
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^tip_height=/) {
            sub(/^tip_height=/, "", $i)
            print $i
            exit
          }
        }
      }' <<<"$tip_out")"
      if [[ "$tip_height" == "none" ]]; then
        printf '0\n'
        return
      elif [[ -n "$tip_height" ]]; then
        printf '%s\n' "$tip_height"
        return
      fi
    fi
  fi
  host="${rpc_addr%:*}"
  port="${rpc_addr##*:}"
  req='{"jsonrpc":"2.0","method":"get_status","id":1}'
  line=""
  if command -v nc >/dev/null 2>&1; then
    line=$(echo "$req" | nc -w 3 "$host" "$port" 2>/dev/null || true)
  fi
  if [[ -z "$line" ]] && command -v curl >/dev/null 2>&1; then
    line=$(curl -sf --max-time 5 -H 'Content-Type: application/json' -d "$req" "http://${host}:${port}/" 2>/dev/null || true)
  fi
  if [[ -z "$line" ]]; then
    printf 'unknown\n'
    return
  fi
  tip_height=$(echo "$line" | sed -n 's/.*"tip_height":\([0-9]*\).*/\1/p')
  if [[ -z "$tip_height" ]] && echo "$line" | grep -q '"tip_height":null'; then
    printf '0\n'
  elif [[ -n "$tip_height" ]]; then
    printf '%s\n' "$tip_height"
  else
    printf 'unknown\n'
  fi
}
