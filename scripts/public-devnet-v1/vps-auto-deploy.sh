#!/usr/bin/env bash
# Safe automatic deploy of origin/main onto the single public-devnet VPS.
#
# Run on the VPS as root (the timer does). Does not SSH. Does not delete
# chain data (.permawrite-devnet-v1 stays). A dirty worktree is refused.
#
#   bash scripts/public-devnet-v1/vps-auto-deploy.sh --plan-only
#   bash scripts/public-devnet-v1/vps-auto-deploy.sh --apply
#
# Consensus and genesis skips: a commit range that touches mfn-consensus,
# mfn-crypto, mfn-bls, or the public_devnet_{v1,fa} genesis/manifest JSON
# is not deployed unless /var/lib/pfpchain-deploy/allow-consensus contains
# that exact origin/main SHA. Checkpoint jsonl files are not in that set.
# See scripts/public-devnet-v1/systemd/README.md.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=vps-auto-deploy-lib.sh
source "$SCRIPT_DIR/vps-auto-deploy-lib.sh"

REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
STATE_DIR="${MFN_DEPLOY_STATE_DIR:-/var/lib/pfpchain-deploy}"
MIN_FREE_MIB="${MFN_DEPLOY_MIN_FREE_MIB:-1536}"
TIP_WAIT_SEC="${MFN_DEPLOY_TIP_WAIT_SEC:-900}"
RPC_HUB="${MFN_DEPLOY_RPC:-127.0.0.1:18731}"
FAUCET_HEALTH="${MFN_DEPLOY_FAUCET_HEALTH:-http://127.0.0.1:8788/health}"
PLAN_ONLY=0
APPLY=0

usage() {
  cat <<'EOF'
usage: vps-auto-deploy.sh [--plan-only|--apply]

Fetch origin/main. When it differs from the deployed SHA, build release mfnd
and mfn-cli into a staging target (CARGO_BUILD_JOBS=2), run --lib tests for
touched crates, swap binaries, then roll services: voters, hub, observer,
proxy, faucet. The hub tip must advance. On failure the previous binaries
are restored, tracked sources are reset to the pre-deploy commit, and the
services are restarted. Chain data is never deleted.

Skips (exit 0, recorded in status.json):
  unchanged, overlap, no runtime change, low memory, faucet busy,
  consensus/genesis range without allow-consensus, a SHA that already failed

Refuses (exit 1): dirty worktree, branch other than main, diverged main,
  build or test failure, tip did not advance (binaries rolled back)

Env:
  MFN_REPO_ROOT, MFN_DEPLOY_STATE_DIR (/var/lib/pfpchain-deploy)
  MFN_DEPLOY_MIN_FREE_MIB (1536), MFN_DEPLOY_CARGO_JOBS (2)
  MFN_DEPLOY_TIP_WAIT_SEC (900), MFN_DEPLOY_RPC, MFN_DEPLOY_FAUCET_HEALTH
  MFN_DEPLOY_SKIP_TESTS=1  emergency only; skips the fast crate subset
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "vps-auto-deploy: unknown argument $1" >&2; usage >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "vps-auto-deploy: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "vps-auto-deploy: plan"
  echo "  flow=flock -> refuse dirty worktree -> git fetch origin/main -> classify paths"
  echo "  build=CARGO_BUILD_JOBS=2 cargo build --release -p mfn-node --bin mfnd -p mfn-cli --bin mfn-cli"
  echo "  staging=$STATE_DIR/staging/target"
  echo "  tests=cargo test -p CRATE --lib --release for touched crates (fast subset)"
  echo "  memory=abort when MemAvailable+SwapFree < ${MIN_FREE_MIB} MiB"
  echo "  order=voters then hub then observer then proxy then faucet"
  echo "  roll=vps-roll-mfnd.sh --skip-pull --skip-build then mfnd-observer then vps-update-observer-rpc-proxy.sh then faucet-http"
  echo "  verify=hub tip advances within ${TIP_WAIT_SEC}s"
  echo "  rollback=previous binaries + git reset --hard to the pre-deploy commit + restart"
  echo "  status=$STATE_DIR/status.json"
  echo "  marker=$STATE_DIR/allow-consensus (exact origin/main SHA)"
  echo "  retry=$STATE_DIR/retry-failed (exact SHA, one shot after a recorded failure)"
  echo "  never=delete chain data"
  echo "  skip=consensus/genesis paths unless allow-consensus matches; checkpoint jsonl is not consensus"
  echo "vps-auto-deploy: PASS plan-only"
  exit 0
fi

log() {
  printf '%s\n' "vps-auto-deploy: $*"
  if command -v logger >/dev/null 2>&1; then
    logger -t pfpchain-deploy -- "$*" || true
  fi
}

status_file="$STATE_DIR/status.json"
deployed_sha=""
attempt_sha=""
previous_sha=""

load_status() {
  deployed_sha="$(mfn_deploy_status_get "$status_file" last_deployed_sha)"
  attempt_sha="$(mfn_deploy_status_get "$status_file" last_attempt_sha)"
  previous_sha="$(mfn_deploy_status_get "$status_file" previous_sha)"
}

write_status() {
  local result="$1"
  local detail="$2"
  local deployed_out="$3"
  local attempt_out="$4"
  local previous_out="$5"
  mfn_deploy_write_status "$STATE_DIR" "$deployed_out" "$attempt_out" "$result" "$detail" "$previous_out"
  log "status result=$result sha=${attempt_out:-none} detail=$detail"
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "vps-auto-deploy: --apply must run as root on the VPS" >&2
  exit 1
fi

mkdir -p "$STATE_DIR"
checked_out=0
exec 9>"$STATE_DIR/deploy.lock"
if ! flock -n 9; then
  log "overlap; another deploy holds $STATE_DIR/deploy.lock"
  exit 0
fi

load_status

if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all)" ]]; then
  log "tracked or untracked changes in $REPO_ROOT; refusing to deploy over local edits"
  git -C "$REPO_ROOT" status --short >&2 || true
  write_status "refused-dirty" "worktree is dirty" "$deployed_sha" "${attempt_sha}" "$previous_sha"
  exit 1
fi

branch="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
if [[ "$branch" != "main" ]]; then
  log "checkout is '$branch', expected main"
  write_status "refused-branch" "HEAD is $branch" "$deployed_sha" "${attempt_sha}" "$previous_sha"
  exit 1
fi

if ! git -C "$REPO_ROOT" fetch origin main; then
  log "git fetch origin main failed"
  write_status "failure-fetch" "git fetch failed" "$deployed_sha" "${attempt_sha}" "$previous_sha"
  exit 1
fi

candidate="$(git -C "$REPO_ROOT" rev-parse origin/main)"
head_now="$(git -C "$REPO_ROOT" rev-parse HEAD)"
log "origin/main=$candidate HEAD=$head_now deployed=${deployed_sha:-none}"

if [[ -n "$deployed_sha" && "$candidate" == "$deployed_sha" ]]; then
  write_status "unchanged" "origin/main matches deployed SHA" "$deployed_sha" "$candidate" "$previous_sha"
  exit 0
fi

prev_result="$(mfn_deploy_status_get "$status_file" result)"
case "$prev_result" in
  failure|rolled-back)
    if [[ "$candidate" == "$attempt_sha" && "$candidate" != "$deployed_sha" ]]; then
      if mfn_deploy_marker_allows "$STATE_DIR/retry-failed" "$candidate"; then
        log "retry-failed marker matches $candidate"
        rm -f "$STATE_DIR/retry-failed"
      else
        write_status "skipped-previous-failure" "SHA already failed; write it to $STATE_DIR/retry-failed to try once" "$deployed_sha" "$candidate" "$previous_sha"
        exit 0
      fi
    fi
    ;;
esac

base="$head_now"
if [[ -n "$deployed_sha" ]]; then
  base="$deployed_sha"
fi
if [[ "$base" != "$candidate" ]]; then
  if ! git -C "$REPO_ROOT" cat-file -e "${base}^{commit}" 2>/dev/null; then
    log "base $base is not in this clone"
    write_status "failure-fetch" "missing base $base" "$deployed_sha" "$candidate" "$previous_sha"
    exit 1
  fi
  if ! git -C "$REPO_ROOT" merge-base --is-ancestor "$base" "$candidate"; then
    log "main has diverged from $base; refusing to reset"
    write_status "refused-diverged" "origin/main is not a descendant of $base" "$deployed_sha" "$candidate" "$previous_sha"
    exit 1
  fi
fi

if [[ "$base" == "$candidate" ]]; then
  paths=""
else
  paths="$(git -C "$REPO_ROOT" diff --name-only "$base" "$candidate")"
fi
scope="$(printf '%s\n' "$paths" | mfn_deploy_scope_for_paths)"
log "scope=$scope"
if [[ -n "$paths" ]]; then
  log "paths:"
  printf '%s\n' "$paths" | sed 's/^/  /'
fi

if [[ "$scope" == "consensus" ]]; then
  if ! mfn_deploy_marker_allows "$STATE_DIR/allow-consensus" "$candidate"; then
    write_status "skipped-consensus" "range touches consensus or genesis; allow-consensus must contain $candidate" "$deployed_sha" "$candidate" "$previous_sha"
    exit 0
  fi
  log "allow-consensus matches $candidate; treating the range as a full roll"
  scope="full"
fi

if [[ "$scope" == "none" ]]; then
  if ! git -C "$REPO_ROOT" merge --ff-only origin/main; then
    write_status "refused-diverged" "fast-forward failed" "$deployed_sha" "$candidate" "$previous_sha"
    exit 1
  fi
  write_status "skipped-no-runtime-change" "no mfnd, cli, or service-script change; HEAD fast-forwarded, services left running" "$candidate" "$candidate" "$previous_sha"
  exit 0
fi

needs_build=0
if [[ -n "$paths" ]]; then
  if printf '%s\n' "$paths" | mfn_deploy_crates_for_paths | grep -q .; then
    needs_build=1
  fi
  if printf '%s\n' "$paths" | grep -Eq '^(Cargo\.toml|Cargo\.lock)$'; then
    needs_build=1
  fi
fi

case "$scope" in
  full|faucet|faucet+proxy)
    if command -v curl >/dev/null 2>&1; then
      fh="$(curl -fsS --max-time 8 "$FAUCET_HEALTH" || true)"
      if [[ -n "$fh" ]]; then
        if printf '%s' "$fh" | python3 -c 'import sys,json
h=json.load(sys.stdin)
raise SystemExit(0 if h.get("busy") or int(h.get("pending_jobs") or 0)>0 else 1)'; then
          write_status "skipped-faucet-busy" "faucet busy or pending_jobs; not restarting" "$deployed_sha" "$candidate" "$previous_sha"
          exit 0
        fi
      else
        log "WARN faucet /health unreachable; continuing"
      fi
    fi
    ;;
esac

if (( needs_build )); then
  meminfo="${MFN_DEPLOY_MEMINFO:-/proc/meminfo}"
  if [[ ! -f "$meminfo" ]]; then
    write_status "skipped-low-memory" "meminfo missing ($meminfo)" "$deployed_sha" "$candidate" "$previous_sha"
    exit 0
  fi
  free_kib="$(mfn_deploy_free_kib "$meminfo")"
  if ! mfn_deploy_memory_sufficient "$free_kib" "$MIN_FREE_MIB"; then
    write_status "skipped-low-memory" "free+swap ${free_kib} KiB below ${MIN_FREE_MIB} MiB" "$deployed_sha" "$candidate" "$previous_sha"
    exit 0
  fi
  log "memory free+swap=${free_kib} KiB threshold=${MIN_FREE_MIB} MiB"
fi

head_before="$(git -C "$REPO_ROOT" rev-parse HEAD)"
if [[ -f "$STATE_DIR/allow-consensus" ]] && mfn_deploy_marker_allows "$STATE_DIR/allow-consensus" "$candidate"; then
  rm -f "$STATE_DIR/allow-consensus"
fi
if ! git -C "$REPO_ROOT" merge --ff-only origin/main; then
  write_status "refused-diverged" "fast-forward failed" "$deployed_sha" "$candidate" "$head_before"
  exit 1
fi
checked_out=1

restore_tree() {
  if (( checked_out == 0 )); then
    return 0
  fi
  log "git reset --hard $head_before (tracked sources only; chain data is not deleted)"
  if ! git -C "$REPO_ROOT" reset --hard "$head_before"; then
    log "git reset --hard failed"
  fi
  checked_out=0
}

fail_attempt() {
  local result="$1"
  local detail="$2"
  restore_tree
  write_status "$result" "$detail" "$deployed_sha" "$candidate" "$head_before"
  exit 1
}

export CARGO_BUILD_JOBS="${MFN_DEPLOY_CARGO_JOBS:-2}"
export CARGO_TARGET_DIR="$STATE_DIR/staging/target"

if (( needs_build )); then
  write_status "in-progress" "building $candidate" "$deployed_sha" "$candidate" "$head_before"
  # shellcheck source=lib-cargo-env.sh
  source "$SCRIPT_DIR/lib-cargo-env.sh"
  log "building release mfnd + mfn-cli jobs=$CARGO_BUILD_JOBS target=$CARGO_TARGET_DIR"
  if ! cargo build --release -p mfn-node --bin mfnd -p mfn-cli --bin mfn-cli; then
    fail_attempt "failure" "cargo build failed"
  fi
  if [[ "${MFN_DEPLOY_SKIP_TESTS:-0}" == "1" ]]; then
    log "WARN MFN_DEPLOY_SKIP_TESTS=1; fast subset skipped"
  else
    crates="$(printf '%s\n' "$paths" | mfn_deploy_crates_for_paths || true)"
    if [[ -n "$crates" ]]; then
      while IFS= read -r crate || [[ -n "$crate" ]]; do
        [[ -z "$crate" ]] && continue
        log "fast subset: cargo test -p $crate --lib --release"
        CARGO_BUILD_JOBS=1
        if ! cargo test -p "$crate" --lib --release -- --test-threads=1; then
          fail_attempt "failure" "tests failed for $crate"
        fi
        CARGO_BUILD_JOBS="${MFN_DEPLOY_CARGO_JOBS:-2}"
      done <<<"$crates"
    else
      log "no touched crates; fast subset is empty"
    fi
  fi
fi

live_dir="$REPO_ROOT/target/release"
prev_dir="$STATE_DIR/previous"
stage_dir="$STATE_DIR/staging/target/release"
swapped_mfnd=0
swapped_cli=0

swap_if_changed() {
  local name="$1"
  local src="$stage_dir/$name"
  if [[ ! -f "$src" ]]; then
    if (( needs_build )); then
      log "missing staged $name"
      return 1
    fi
    return 0
  fi
  if [[ -f "$live_dir/$name" ]] && cmp -s "$src" "$live_dir/$name"; then
    log "$name unchanged"
    return 0
  fi
  mfn_deploy_atomic_install "$src" "$live_dir" "$name" "$prev_dir"
  log "installed $name"
  if [[ "$name" == "mfnd" ]]; then
    swapped_mfnd=1
  else
    swapped_cli=1
  fi
}

if (( needs_build )); then
  case "$scope" in
    full)
      swap_if_changed mfnd || fail_attempt "failure" "mfnd swap failed"
      swap_if_changed mfn-cli || fail_attempt "failure" "mfn-cli swap failed"
      ;;
    faucet|faucet+proxy)
      swap_if_changed mfn-cli || fail_attempt "failure" "mfn-cli swap failed"
      ;;
  esac
fi

tip_height() {
  local cli="$1"
  local rpc="$2"
  local out
  if [[ ! -x "$cli" ]]; then
    printf ''
    return 0
  fi
  out="$("$cli" --rpc "$rpc" tip 2>/dev/null || true)"
  printf '%s\n' "$out" | sed -n 's/.*tip_height=\([0-9][0-9]*\).*/\1/p' | head -n 1
}

wait_tip_advances() {
  local before="$1"
  local cli="$2"
  local deadline now seen
  deadline=$((SECONDS + TIP_WAIT_SEC))
  seen=""
  while (( SECONDS < deadline )); do
    now="$(tip_height "$cli" "$RPC_HUB")"
    if [[ "$now" =~ ^[0-9]+$ ]]; then
      if [[ "$before" =~ ^[0-9]+$ ]]; then
        if (( now > before )); then
          log "tip advanced ${before} -> ${now}"
          return 0
        fi
      elif [[ -z "$seen" ]]; then
        seen="$now"
        log "hub tip readable tip_height=$now; waiting for the next block"
      elif (( now > seen )); then
        log "tip advanced ${seen} -> ${now}"
        return 0
      fi
    fi
    sleep 5
  done
  log "tip did not advance (before=${before:-unread})"
  return 1
}

start_p2p_forwards() {
  local unit
  for unit in mfn-p2p-forward-hub mfn-p2p-forward-19002 mfn-p2p-forward-19003 mfn-p2p-forward-19004; do
    if systemctl cat "${unit}.service" >/dev/null 2>&1; then
      systemctl start "${unit}.service" || log "WARN ${unit} did not start"
    else
      log "${unit} is not installed (skipped)"
    fi
  done
}

roll_full() {
  log "roll voters then hub via vps-roll-mfnd.sh"
  # Explicit returns: this function is also called from `if`, which disables set -e.
  MFN_ROLL_ALLOW_RED_CI=1 bash "$SCRIPT_DIR/vps-roll-mfnd.sh" --apply --skip-pull --skip-build --rpc "$RPC_HUB" || return 1
  log "restart observer"
  systemctl restart mfnd-observer.service || return 1
  log "roll observer-rpc-proxy via vps-update-observer-rpc-proxy.sh"
  bash "$SCRIPT_DIR/vps-update-observer-rpc-proxy.sh" --apply || return 1
  log "restart faucet-http"
  systemctl restart faucet-http.service || return 1
  start_p2p_forwards
}

roll_faucet() {
  systemctl restart faucet-http.service || return 1
}

roll_proxy() {
  bash "$SCRIPT_DIR/vps-update-observer-rpc-proxy.sh" --apply || return 1
}

roll_scope() {
  case "$scope" in
    full) roll_full ;;
    faucet) roll_faucet ;;
    proxy) roll_proxy ;;
    faucet+proxy)
      roll_proxy
      roll_faucet
      ;;
    *)
      log "no service roll for scope=$scope"
      ;;
  esac
}

restore_bins() {
  if (( swapped_mfnd )); then
    if mfn_deploy_restore_previous "$live_dir" mfnd "$prev_dir"; then
      log "restored previous mfnd"
    else
      log "no previous mfnd to restore"
    fi
  fi
  if (( swapped_cli )); then
    if mfn_deploy_restore_previous "$live_dir" mfn-cli "$prev_dir"; then
      log "restored previous mfn-cli"
    else
      log "no previous mfn-cli to restore"
    fi
  fi
}

cli_bin="$live_dir/mfn-cli"
tip_before="$(tip_height "$cli_bin" "$RPC_HUB")"
log "tip_before=${tip_before:-unread} rpc=$RPC_HUB scope=$scope"

rollback_running() {
  local why="$1"
  restore_bins
  restore_tree
  roll_scope || log "rollback restart also failed"
  write_status "rolled-back" "$why" "$deployed_sha" "$candidate" "$head_before"
  exit 1
}

if ! roll_scope; then
  log "roll failed; rolling back"
  rollback_running "service roll failed; previous binaries restored"
fi

if ! wait_tip_advances "$tip_before" "$cli_bin"; then
  log "tip did not advance; rolling back"
  rollback_running "tip did not advance within ${TIP_WAIT_SEC}s"
fi

write_status "success" "deployed $candidate scope=$scope" "$candidate" "$candidate" "$head_before"
log "OK deployed=$candidate tip=$(tip_height "$cli_bin" "$RPC_HUB")"
