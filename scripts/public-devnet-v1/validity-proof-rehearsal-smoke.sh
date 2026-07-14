#!/usr/bin/env bash
# Lane 4 / F5 phase 4b.1: plan-only validity-proof wire + P2P tag gate.
set -euo pipefail

usage() {
  echo "usage: $0 [--plan-only]" >&2
}

PLAN_ONLY=1
for arg in "$@"; do
  case "$arg" in
    --plan-only) PLAN_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "validity-proof-rehearsal-smoke: unknown arg: $arg" >&2; usage >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/FRAUD_PROOFS.md"
CONSENSUS="$REPO_ROOT/mfn-consensus/src/validity_proof.rs"
NET="$REPO_ROOT/mfn-net/src/validity_proof_v1.rs"
FRAME="$REPO_ROOT/mfn-net/src/frame.rs"
GOSSIP="$REPO_ROOT/mfn-net/src/gossip.rs"
NODE_GOSSIP="$REPO_ROOT/mfn-node/src/p2p_gossip.rs"
SERVE="$REPO_ROOT/mfn-net/src/serve.rs"

for path in "$DOC" "$CONSENSUS" "$NET" "$FRAME" "$GOSSIP" "$NODE_GOSSIP" "$SERVE"; do
  if [[ ! -f "$path" ]]; then
    echo "validity-proof-rehearsal-smoke: missing $path" >&2
    exit 1
  fi
done

for needle in verify_validity_proof_v1 VALIDITY_PROOF_V1_TAG 0x14 "phase 4b.1"; do
  if ! grep -Fq "$needle" "$DOC"; then
    echo "validity-proof-rehearsal-smoke: FRAUD_PROOFS.md missing: $needle" >&2
    exit 1
  fi
done
if ! grep -Fq build_apply_block_replay_validity_proof "$CONSENSUS"; then
  echo "validity-proof-rehearsal-smoke: validity_proof.rs missing replay builder" >&2
  exit 1
fi
if ! grep -q build_stark_digest_stub_validity_proof "$CONSENSUS"; then
  echo "validity-proof-rehearsal-smoke: validity_proof.rs missing stark stub builder" >&2
  exit 1
fi
if ! grep -q build_stark_winterfell_validity_proof "$CONSENSUS"; then
  echo "validity-proof-rehearsal-smoke: validity_proof.rs missing winterfell builder" >&2
  exit 1
fi
if ! grep -Fq VALIDITY_PROOF_V1_TAG "$NET"; then
  echo "validity-proof-rehearsal-smoke: validity_proof_v1.rs missing tag constant" >&2
  exit 1
fi
if ! grep -Fq VALIDITY_PROOF_V1_TAG "$FRAME"; then
  echo "validity-proof-rehearsal-smoke: frame.rs must document VALIDITY_PROOF_V1_TAG" >&2
  exit 1
fi

phase4a_needles=(
  "on_validity_proof_v1:$GOSSIP"
  "send_validity_proof_v1:$GOSSIP"
  "push_validity_proof_gossip_to_peer:$GOSSIP"
  "verify_validity_proof_v1:$NODE_GOSSIP"
  "mfnd_validity_proof_valid:$SERVE"
)
for entry in "${phase4a_needles[@]}"; do
  needle="${entry%%:*}"
  file="${entry#*:}"
  if ! grep -Fq "$needle" "$file"; then
    echo "validity-proof-rehearsal-smoke: $file missing: $needle" >&2
    exit 1
  fi
done

echo "validity-proof-rehearsal-smoke: plan"
echo "  docs=docs/FRAUD_PROOFS.md"
echo "  consensus=mfn_consensus::validity_proof"
echo "  p2p_tag=0x14 VALIDITY_PROOF_V1_TAG"
echo "  witness=apply_block_replay + stark_digest_stub + stark_winterfell (phase 4b.1)"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "validity-proof-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "validity-proof-rehearsal-smoke: live mode not implemented" >&2
exit 1
