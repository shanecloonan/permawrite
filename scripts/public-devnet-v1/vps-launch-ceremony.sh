#!/usr/bin/env bash
# Lane 7: VPS launch ceremony — status, plan, and go/no-go check (TL-5 through TL-9).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_ONLY=0
CHECK_ONLY=0

usage() {
  cat <<'EOF'
usage: vps-launch-ceremony.sh [--plan-only] [--check]

  (default)  launch-status + optional go/no-go when evidence exists
  --plan-only  print ordered TL-5..TL-9 commands (no mesh start)
  --check      run launch-go-no-go.sh (exits non-zero if gates fail)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --check) CHECK_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "vps-launch-ceremony: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if (( PLAN_ONLY == 1 )); then
  cat <<'EOF'
vps-launch-ceremony: ordered VPS path (Lane 7)

  Pre   bash scripts/public-devnet-v1/vps-execution-checklist.sh
        # laptop gate before provisioning (vps-execution-checklist.v2)

  TL-5  bash scripts/public-devnet-v1/vps-preflight.sh
        bash scripts/public-devnet-v1/vps-internet-soak.sh
        # archive scripts/public-devnet-v1/evidence/vps-internet-soak-linux-*.txt

  TL-6  bash scripts/public-devnet-v1/vps-participant-rehearsal.sh --no-start --no-stop
        # archive vps-participant-rehearsal-observer-linux-*.txt

  TL-7  human sign-off — docs/TESTNET_GENESIS_CEREMONY.md (Path A toy keys typical)

  TL-8  bash scripts/public-devnet-v1/publish-seed-nodes.sh --public-ip YOUR_IP --apply
        bash scripts/public-devnet-v1/publish-checkpoint-log.sh --apply
        git commit manifest + checkpoints.jsonl + share docs/TESTNET_INVITE.md

  TL-9  bash scripts/public-devnet-v1/launch-go-no-go.sh
        complete OPERATORS.md go/no-go + named launch-day watchers

Docs: docs/VPS_PROVISION.md  docs/VPS_SINGLE_BOX_LAUNCH.md  docs/TESTNET_LAUNCH.md
EOF
  exit 0
fi

echo "vps-launch-ceremony: === launch-status ==="
bash "$SCRIPT_DIR/launch-status.sh"
echo ""

if (( CHECK_ONLY == 1 )); then
  echo "vps-launch-ceremony: === launch-go-no-go ==="
  bash "$SCRIPT_DIR/launch-go-no-go.sh"
  exit $?
fi

# Default: run go/no-go only when VPS evidence exists (informational otherwise).
if compgen -G "$SCRIPT_DIR/evidence/vps-internet-soak-linux-*.txt" >/dev/null 2>&1 || \
   compgen -G "$SCRIPT_DIR/evidence/vps-participant-rehearsal-*.txt" >/dev/null 2>&1 || \
   [[ "$(python3 -c "import json; print(len(json.load(open('$SCRIPT_DIR/../../mfn-node/testdata/public_devnet_v1.manifest.json')).get('seed_nodes',[])))" 2>/dev/null || echo 0)" -gt 0 ]]; then
  echo "vps-launch-ceremony: === launch-go-no-go (evidence or seeds present) ==="
  bash "$SCRIPT_DIR/launch-go-no-go.sh" || true
else
  echo "vps-launch-ceremony: skip go/no-go (no VPS evidence yet); use --check to force"
  if bash "$SCRIPT_DIR/launch-status.sh" 2>/dev/null | grep -q "local_rc_complete=true"; then
    echo "vps-launch-ceremony: local RC complete — provision VPS per docs/VPS_PROVISION.md"
  fi
  echo "vps-launch-ceremony: next: bash scripts/public-devnet-v1/vps-internet-soak.sh (on VPS)"
fi
