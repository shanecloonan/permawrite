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
