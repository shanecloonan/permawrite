#!/usr/bin/env bash
# B-22 Path A: create a new maintainer signer when the original seed is unavailable.
# Writes seed ONLY to a local env file (never commit). Appends a near-tip log entry.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
SEED_ENV="${MFN_CHECKPOINT_SIGNER_ENV:-$HOME/.mfn/checkpoint-signer.env}"
LOG_PATH="${MFN_CHECKPOINT_LOG:-$REPO_ROOT/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl}"
SIGNER_ID="${MFN_CHECKPOINT_LOG_SIGNER_ID:-permawrite-maintainer-path-a-2}"
# Do not seed RPC from $1 before getopt — bare `--apply` would become the RPC addr.
RPC=""
APPLY=0
PLAN_ONLY=0

usage() {
  cat <<'EOF'
usage: bootstrap-path-a-checkpoint-signer.sh [--plan-only|--apply] [--rpc HOST:PORT]

Path A public-devnet only. When maintainer-1 seed is lost, mint a new signer,
persist seed under ~/.mfn/checkpoint-signer.env (gitignored path), and publish
a tip attestation via publish-checkpoint-log.sh.

Never commit the seed file. Commit only the updated checkpoints.jsonl.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    --rpc) RPC="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      if [[ -z "$RPC" && "$1" != --* ]]; then
        RPC="$1"
        shift
      else
        echo "bootstrap-path-a-checkpoint-signer: unknown argument $1" >&2
        usage >&2
        exit 1
      fi
      ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "bootstrap-path-a-checkpoint-signer: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "bootstrap-path-a-checkpoint-signer: plan"
  echo "  seed_env=$SEED_ENV"
  echo "  signer_id=$SIGNER_ID"
  echo "  log=$LOG_PATH"
  echo "  flow=openssl rand -hex 32 -> write env -> publish-checkpoint-log.sh --apply"
  echo "  warning=Path A toy maintainer; not a security root of trust"
  echo "bootstrap-path-a-checkpoint-signer: PASS plan-only"
  exit 0
fi

if [[ -z "$RPC" ]]; then
  RPC="127.0.0.1:18731"
fi

mkdir -p "$(dirname "$SEED_ENV")"
if [[ ! -f "$SEED_ENV" ]]; then
  seed="$(openssl rand -hex 32)"
  umask 077
  cat >"$SEED_ENV" <<EOF
# Path A checkpoint maintainer (B-22). DO NOT COMMIT.
export MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX=$seed
export MFN_CHECKPOINT_LOG_SIGNER_ID=$SIGNER_ID
EOF
  echo "bootstrap-path-a-checkpoint-signer: created $SEED_ENV"
else
  echo "bootstrap-path-a-checkpoint-signer: reusing $SEED_ENV"
fi

# shellcheck disable=SC1090
source "$SEED_ENV"
export MFN_CHECKPOINT_LOG_SIGNER_SEED_HEX
export MFN_CHECKPOINT_LOG_SIGNER_ID="${MFN_CHECKPOINT_LOG_SIGNER_ID:-$SIGNER_ID}"

bash "$SCRIPT_DIR/publish-checkpoint-log.sh" --rpc "$RPC" --log "$LOG_PATH" --signer-id "$MFN_CHECKPOINT_LOG_SIGNER_ID" --apply
echo "bootstrap-path-a-checkpoint-signer: OK — commit $LOG_PATH only; keep seed offline"
