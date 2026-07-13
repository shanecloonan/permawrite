#!/usr/bin/env bash
# Lane 4 / F5: plan-only fraud-proof doc + module wiring gate (phase 0 + phase 1 gossip).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/FRAUD_PROOFS.md"
PROBLEMS="$REPO_ROOT/docs/PROBLEMS.md"
SECURITY="$REPO_ROOT/docs/SECURITY_CONSIDERATIONS.md"
CONSENSUS="$REPO_ROOT/mfn-consensus/src/fraud_proof.rs"
NET="$REPO_ROOT/mfn-net/src/fraud_proof_v1.rs"
FRAME="$REPO_ROOT/mfn-net/src/frame.rs"
GOSSIP="$REPO_ROOT/mfn-net/src/gossip.rs"
NODE_GOSSIP="$REPO_ROOT/mfn-node/src/p2p_gossip.rs"
NODE_FANOUT="$REPO_ROOT/mfn-node/src/p2p_fanout.rs"
FRAUD_CONTEST="$REPO_ROOT/mfn-node/src/fraud_contest.rs"
MFND_SMOKE="$REPO_ROOT/mfn-node/tests/mfnd_smoke.rs"
DISPATCH="$REPO_ROOT/mfn-rpc/src/dispatch.rs"

usage() {
  cat <<EOF
Usage: $(basename "$0") --plan-only
EOF
}

PLAN_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "fraud-proof-rehearsal-smoke: unknown arg: $1" >&2; usage >&2; exit 1 ;;
  esac
done

for path in "$DOC" "$PROBLEMS" "$SECURITY" "$CONSENSUS" "$NET" "$FRAME" "$GOSSIP" "$NODE_GOSSIP" "$NODE_FANOUT" "$FRAUD_CONTEST" "$DISPATCH"; do
  if [[ ! -f "$path" ]]; then
    echo "fraud-proof-rehearsal-smoke: missing $path" >&2
    exit 1
  fi
done

for needle in verify_body_root_fraud_proof FRAUD_PROOF_SOFT_FINALITY_SLOTS 0x13; do
  if ! grep -Fq "$needle" "$DOC"; then
    echo "fraud-proof-rehearsal-smoke: FRAUD_PROOFS.md missing: $needle" >&2
    exit 1
  fi
done

if ! grep -Fq "fraud-proof" "$PROBLEMS"; then
  echo "fraud-proof-rehearsal-smoke: PROBLEMS.md missing fraud-proof roadmap" >&2
  exit 1
fi
if ! grep -Fq "FRAUD_PROOF_V1_TAG" "$FRAME"; then
  echo "fraud-proof-rehearsal-smoke: frame.rs must document FRAUD_PROOF_V1_TAG" >&2
  exit 1
fi
if ! grep -Fq "FRAUD_PROOF_V1_TAG" "$NET"; then
  echo "fraud-proof-rehearsal-smoke: fraud_proof_v1.rs missing tag constant" >&2
  exit 1
fi
for needle in on_fraud_proof_v1 send_fraud_proof_v1 push_fraud_proof_gossip_to_peer fanout_fraud_proof mfnd_fraud_proof_valid; do
  case "$needle" in
    on_fraud_proof_v1|send_fraud_proof_v1|push_fraud_proof_gossip_to_peer)
      if ! grep -Fq "$needle" "$GOSSIP"; then
        echo "fraud-proof-rehearsal-smoke: gossip.rs missing phase 1: $needle" >&2
        exit 1
      fi
      ;;
    fanout_fraud_proof)
      if ! grep -Fq "$needle" "$NODE_FANOUT"; then
        echo "fraud-proof-rehearsal-smoke: p2p_fanout.rs missing phase 1: $needle" >&2
        exit 1
      fi
      ;;
    mfnd_fraud_proof_valid)
      if ! grep -Fq "$needle" "$REPO_ROOT/mfn-net/src/serve.rs"; then
        echo "fraud-proof-rehearsal-smoke: serve.rs missing phase 1 log: $needle" >&2
        exit 1
      fi
      ;;
    *)
      if ! grep -Fq "$needle" "$NODE_GOSSIP"; then
        echo "fraud-proof-rehearsal-smoke: p2p_gossip.rs missing phase 1: $needle" >&2
        exit 1
      fi
      ;;
  esac
done
if ! grep -Fq "verify_interactive_fraud_proof" "$NODE_GOSSIP"; then
  echo "fraud-proof-rehearsal-smoke: p2p_gossip.rs missing verify_interactive_fraud_proof" >&2
  exit 1
fi
if ! grep -Fq "verify_coinbase_amount_fraud_proof" "$CONSENSUS"; then
  echo "fraud-proof-rehearsal-smoke: fraud_proof.rs missing phase 2 verify_coinbase_amount_fraud_proof" >&2
  exit 1
fi
if ! grep -Fq "verify_interactive_fraud_proof" "$CONSENSUS"; then
  echo "fraud-proof-rehearsal-smoke: fraud_proof.rs missing verify_interactive_fraud_proof" >&2
  exit 1
fi
if ! grep -Fq "COINBASE_FRAUD_PROOF_VERSION" "$CONSENSUS"; then
  echo "fraud-proof-rehearsal-smoke: fraud_proof.rs missing COINBASE_FRAUD_PROOF_VERSION" >&2
  exit 1
fi
if ! grep -Fq "verify_tx_fraud_proof" "$CONSENSUS"; then
  echo "fraud-proof-rehearsal-smoke: fraud_proof.rs missing phase 3 verify_tx_fraud_proof" >&2
  exit 1
fi
if ! grep -Fq "RingMemberUtxo" "$CONSENSUS"; then
  echo "fraud-proof-rehearsal-smoke: fraud_proof.rs missing phase 3b RingMemberUtxo" >&2
  exit 1
fi
if ! grep -Fq "RING_FRAUD_DEDUP_KIND" "$CONSENSUS"; then
  echo "fraud-proof-rehearsal-smoke: fraud_proof.rs missing RING_FRAUD_DEDUP_KIND" >&2
  exit 1
fi
if ! grep -Fq "fraud_proof_producer_slash_hint" "$CONSENSUS"; then
  echo "fraud-proof-rehearsal-smoke: fraud_proof.rs missing fraud_proof_producer_slash_hint" >&2
  exit 1
fi
if ! grep -Fq "mfnd_fraud_proof_producer_slash_hint" "$REPO_ROOT/mfn-net/src/serve.rs"; then
  echo "fraud-proof-rehearsal-smoke: serve.rs missing mfnd_fraud_proof_producer_slash_hint" >&2
  exit 1
fi
if ! grep -Fq "RingMember" "$NODE_GOSSIP"; then
  echo "fraud-proof-rehearsal-smoke: p2p_gossip.rs missing RingMember verdict handling" >&2
  exit 1
fi
if ! grep -Fq "FraudContestRegistry" "$FRAUD_CONTEST"; then
  echo "fraud-proof-rehearsal-smoke: fraud_contest.rs missing FraudContestRegistry" >&2
  exit 1
fi
if ! grep -Fq "list_fraud_contests" "$DISPATCH"; then
  echo "fraud-proof-rehearsal-smoke: dispatch.rs missing list_fraud_contests" >&2
  exit 1
fi
if ! grep -Fq "mfnd_serve_list_fraud_contests" "$MFND_SMOKE"; then
  echo "fraud-proof-rehearsal-smoke: mfnd_smoke.rs missing list_fraud_contests integration test" >&2
  exit 1
fi

if ! grep -Fq "InvalidClsag" "$CONSENSUS"; then
  echo "fraud-proof-rehearsal-smoke: fraud_proof.rs missing phase 3 InvalidClsag" >&2
  exit 1
fi
if ! grep -Fq "InvalidSpora" "$CONSENSUS"; then
  echo "fraud-proof-rehearsal-smoke: fraud_proof.rs missing phase 3 InvalidSpora" >&2
  exit 1
fi

echo "fraud-proof-rehearsal-smoke: plan"
echo "  docs=docs/FRAUD_PROOFS.md"
echo "  consensus=mfn_consensus::fraud_proof"
echo "  p2p_tag=0x13 FRAUD_PROOF_V1_TAG"
echo "  phase=1b fraud contest registry + list_fraud_contests RPC"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "fraud-proof-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "fraud-proof-rehearsal-smoke: live mode not implemented" >&2
exit 1