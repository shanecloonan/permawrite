#!/usr/bin/env bash
# Print a safe, explicit permanence recovery plan without mutating wallet or node state.
set -euo pipefail

RPC="127.0.0.1:<RPC>"
WALLET="./wallet.json"
COMMIT_HASH="<COMMIT_HASH_HEX>"
OUTPUT_PATH="./restored.bin"
DATA_DIR=""
REPLACE=0
PEERS=()

usage() {
  cat <<'EOF'
usage: recovery-plan.sh [options]

Options:
  --rpc HOST:PORT       mfnd JSON-RPC address
  --wallet FILE         wallet used for local upload artifacts
  --commit HASH         storage commitment hash
  --output FILE         restored payload output path
  --peer HOST:PORT      HTTP chunk peer; repeat for quorum peers
  --data-dir DIR        replica mfnd data dir for P2P inbox assembly
  --replace             include replace/overwrite tokens in generated commands
  -h, --help            show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc)
      RPC="${2:-}"
      shift 2
      ;;
    --wallet)
      WALLET="${2:-}"
      shift 2
      ;;
    --commit)
      COMMIT_HASH="${2:-}"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="${2:-}"
      shift 2
      ;;
    --peer)
      PEERS+=("${2:-}")
      shift 2
      ;;
    --data-dir)
      DATA_DIR="${2:-}"
      shift 2
      ;;
    --replace)
      REPLACE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "recovery-plan: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

replace_token=""
if (( REPLACE )); then
  replace_token=" replace"
fi
peer_list="<PEER_HTTP>"
if (( ${#PEERS[@]} > 0 )); then
  peer_list="${PEERS[*]}"
fi
support_peer="<PEER_HTTP>"
if (( ${#PEERS[@]} > 0 )); then
  support_peer="${PEERS[0]}"
fi
data_dir_text="${DATA_DIR:-<REPLICA_DATA_DIR>}"

cat <<EOF
recovery-plan: read-only plan
  rpc=$RPC
  wallet=$WALLET
  commit_hash=$COMMIT_HASH
  output_path=$OUTPUT_PATH
  replace=$([[ "$REPLACE" -eq 1 ]] && echo true || echo false)

Safety first:
  1. Back up the wallet file and {wallet_stem}.upload-artifacts/ before any repair.
  2. Run a support bundle before mutating local artifacts:
     bash scripts/public-devnet-v1/support-bundle.sh --rpc $RPC --wallet $WALLET --commit $COMMIT_HASH --peer $support_peer --data-dir $data_dir_text
  3. Use replace only when the existing artifact/output file may be overwritten.

HTTP peer restore (rebuild artifact + write restored payload):
  mfn-cli --rpc $RPC --wallet $WALLET uploads fetch-http $COMMIT_HASH $OUTPUT_PATH $peer_list$replace_token --json

P2P inbox restore (inspect, assemble artifact, then export payload):
  mfn-cli --rpc $RPC operator inbox-status $COMMIT_HASH $data_dir_text --json
  mfn-cli --rpc $RPC --wallet $WALLET operator assemble-inbox $COMMIT_HASH $data_dir_text$replace_token --json
  mfn-cli --wallet $WALLET uploads retrieve $COMMIT_HASH $OUTPUT_PATH$replace_token

After restore:
  Compare the restored payload hash with the uploader or known-good peer before proving.
  mfn-cli --rpc $RPC --wallet $WALLET operator prove $COMMIT_HASH --json
  mfn-cli --rpc $RPC uploads list --include-claims --json
EOF
