#!/usr/bin/env bash
# shellcheck shell=bash
# Decisions for vps-auto-deploy.sh. Source this file; do not execute it.
# Chain data is never named here. Callers must not delete .permawrite-devnet-v1.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "vps-auto-deploy-lib: source this file; do not execute it" >&2
  exit 1
fi

# Class of one repo-relative path:
#   consensus  rules or genesis/manifest params (deploy only with allow-consensus)
#   full       mfnd or a unit script the validators execute
#   faucet     mfn-cli or faucet-http
#   proxy      observer-rpc-proxy
#   none       docs, board, checkpoint logs, anything else
mfn_deploy_class_for_path() {
  local p="$1"
  case "$p" in
    mfn-consensus/*|mfn-crypto/*|mfn-bls/*)
      printf '%s\n' consensus
      ;;
    mfn-node/testdata/public_devnet_v1.json|\
      mfn-node/testdata/public_devnet_fa.json|\
      mfn-node/testdata/public_devnet_v1.manifest.json|\
      mfn-node/testdata/public_devnet_fa.manifest.json)
      printf '%s\n' consensus
      ;;
    mfn-node/testdata/public_devnet_v1.checkpoints.jsonl|\
      mfn-node/testdata/public_devnet_fa.checkpoints.jsonl)
      printf '%s\n' none
      ;;
    mfn-node/*|mfn-runtime/*|mfn-net/*|mfn-store/*|mfn-rpc/*|mfn-storage/*|\
      Cargo.toml|Cargo.lock|\
      scripts/public-devnet-v1/start-hub.sh|\
      scripts/public-devnet-v1/start-voter.sh|\
      scripts/public-devnet-v1/start-observer.sh|\
      scripts/public-devnet-v1/config.env|\
      scripts/public-devnet-v1/config.fa.env|\
      scripts/public-devnet-v1/systemd/mfnd-hub.service|\
      scripts/public-devnet-v1/systemd/mfnd-v1.service|\
      scripts/public-devnet-v1/systemd/mfnd-v2.service|\
      scripts/public-devnet-v1/systemd/mfnd-observer.service)
      printf '%s\n' full
      ;;
    mfn-cli/*|mfn-wallet/*|mfn-light/*|mfn-checkpoint-log/*|mfn-storage-operator/*|\
      scripts/public-devnet-v1/faucet-http.mjs|\
      scripts/public-devnet-v1/systemd/faucet-http.service)
      printf '%s\n' faucet
      ;;
    scripts/public-devnet-v1/observer-rpc-proxy.mjs|\
      scripts/public-devnet-v1/observer-rpc-proxy.service)
      printf '%s\n' proxy
      ;;
    *)
      printf '%s\n' none
      ;;
  esac
}

# stdin: repo-relative paths, one per line.
# stdout: consensus | full | faucet | proxy | faucet+proxy | none
# consensus wins over every other class in the same range.
mfn_deploy_scope_for_paths() {
  local scope="none"
  local saw_faucet=0
  local saw_proxy=0
  local p class
  while IFS= read -r p || [[ -n "$p" ]]; do
    [[ -z "$p" ]] && continue
    class="$(mfn_deploy_class_for_path "$p")"
    case "$class" in
      consensus)
        scope="consensus"
        ;;
      full)
        if [[ "$scope" != "consensus" ]]; then
          scope="full"
        fi
        ;;
      faucet)
        saw_faucet=1
        ;;
      proxy)
        saw_proxy=1
        ;;
      none) ;;
      *) ;;
    esac
  done
  if [[ "$scope" == "consensus" || "$scope" == "full" ]]; then
    printf '%s\n' "$scope"
    return 0
  fi
  if (( saw_faucet && saw_proxy )); then
    printf '%s\n' "faucet+proxy"
  elif (( saw_faucet )); then
    printf '%s\n' "faucet"
  elif (( saw_proxy )); then
    printf '%s\n' "proxy"
  else
    printf '%s\n' "none"
  fi
}

# Workspace crate for a path, or empty when the path has no crate tests.
mfn_deploy_crate_for_path() {
  local p="$1"
  case "$p" in
    mfn-node/testdata/public_devnet_v1.checkpoints.jsonl|\
      mfn-node/testdata/public_devnet_fa.checkpoints.jsonl)
      ;;
    mfn-consensus/*) printf '%s\n' mfn-consensus ;;
    mfn-node/*) printf '%s\n' mfn-node ;;
    mfn-cli/*) printf '%s\n' mfn-cli ;;
    mfn-wallet/*) printf '%s\n' mfn-wallet ;;
    mfn-runtime/*) printf '%s\n' mfn-runtime ;;
    mfn-net/*) printf '%s\n' mfn-net ;;
    mfn-rpc/*) printf '%s\n' mfn-rpc ;;
    mfn-light/*) printf '%s\n' mfn-light ;;
    mfn-storage/*) printf '%s\n' mfn-storage ;;
    mfn-storage-operator/*) printf '%s\n' mfn-storage-operator ;;
    mfn-crypto/*) printf '%s\n' mfn-crypto ;;
    mfn-store/*) printf '%s\n' mfn-store ;;
    mfn-bls/*) printf '%s\n' mfn-bls ;;
    mfn-checkpoint-log/*) printf '%s\n' mfn-checkpoint-log ;;
    *) ;;
  esac
}

# stdin: paths. stdout: unique crate names, one per line.
mfn_deploy_crates_for_paths() {
  local p crate already s
  local -a seen=()
  while IFS= read -r p || [[ -n "$p" ]]; do
    [[ -z "$p" ]] && continue
    crate="$(mfn_deploy_crate_for_path "$p")"
    [[ -z "$crate" ]] && continue
    already=0
    for s in "${seen[@]+"${seen[@]}"}"; do
      if [[ "$s" == "$crate" ]]; then
        already=1
      fi
    done
    if (( already == 0 )); then
      seen+=("$crate")
      printf '%s\n' "$crate"
    fi
  done
}

# Sum MemAvailable and SwapFree from a meminfo file. KiB.
mfn_deploy_free_kib() {
  local src="$1"
  awk '/^(MemAvailable|SwapFree):/ { s += $2 } END { printf "%d", s + 0 }' "$src"
}

# Return 0 when free_kib is at least min_mib mebibytes.
mfn_deploy_memory_sufficient() {
  local free_kib="$1"
  local min_mib="$2"
  local min_kib=$((min_mib * 1024))
  (( free_kib >= min_kib ))
}

# Marker file contains exactly the candidate SHA (whitespace ignored).
mfn_deploy_marker_allows() {
  local file="$1"
  local sha="$2"
  local got
  [[ -f "$file" ]] || return 1
  got="$(tr -d '[:space:]' <"$file")"
  [[ -n "$sha" && "$got" == "$sha" ]]
}

mfn_deploy_status_get() {
  local file="$1"
  local key="$2"
  if [[ ! -f "$file" ]]; then
    printf ''
    return 0
  fi
  python3 - "$file" "$key" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    doc = json.load(fh)
val = doc.get(sys.argv[2], "")
if val is None:
    val = ""
sys.stdout.write(str(val))
PY
}

# Atomic status.json. Does not delete any chain directory.
mfn_deploy_write_status() {
  local dir="$1"
  local deployed="$2"
  local attempt="$3"
  local result="$4"
  local detail="$5"
  local previous="$6"
  local tmp
  mkdir -p "$dir"
  tmp="$dir/status.json.tmp.$$"
  MFN_STATUS_DEPLOYED="$deployed" \
    MFN_STATUS_ATTEMPT="$attempt" \
    MFN_STATUS_RESULT="$result" \
    MFN_STATUS_DETAIL="$detail" \
    MFN_STATUS_PREVIOUS="$previous" \
    python3 - "$tmp" <<'PY'
import json
import os
import sys
import time
doc = {
    "schema": "pfpchain-deploy-status.v1",
    "last_deployed_sha": os.environ.get("MFN_STATUS_DEPLOYED", ""),
    "last_attempt_sha": os.environ.get("MFN_STATUS_ATTEMPT", ""),
    "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "result": os.environ.get("MFN_STATUS_RESULT", ""),
    "detail": os.environ.get("MFN_STATUS_DETAIL", ""),
    "previous_sha": os.environ.get("MFN_STATUS_PREVIOUS", ""),
}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
PY
  mv -f "$tmp" "$dir/status.json"
  chmod 644 "$dir/status.json"
}

# Copy src onto dest_dir/name via a temp file on the destination, keeping
# the previous dest bytes in prev_dir/name for rollback.
mfn_deploy_atomic_install() {
  local src="$1"
  local dest_dir="$2"
  local name="$3"
  local prev_dir="$4"
  local tmp
  [[ -f "$src" ]] || return 1
  mkdir -p "$dest_dir" "$prev_dir"
  if [[ -f "$dest_dir/$name" ]]; then
    cp -a "$dest_dir/$name" "$prev_dir/$name"
  fi
  tmp="$dest_dir/.$name.deploying.$$"
  cp -a "$src" "$tmp"
  chmod 755 "$tmp"
  mv -f "$tmp" "$dest_dir/$name"
}

mfn_deploy_restore_previous() {
  local dest_dir="$1"
  local name="$2"
  local prev_dir="$3"
  local tmp
  [[ -f "$prev_dir/$name" ]] || return 1
  mkdir -p "$dest_dir"
  tmp="$dest_dir/.$name.rollback.$$"
  cp -a "$prev_dir/$name" "$tmp"
  chmod 755 "$tmp"
  mv -f "$tmp" "$dest_dir/$name"
}
