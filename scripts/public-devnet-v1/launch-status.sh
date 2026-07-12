#!/usr/bin/env bash
# Lane 7 — read-only internet-facing testnet launch posture (Linux/macOS).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.manifest.json"
CHECKPOINT_LOG="$REPO_ROOT/mfn-node/testdata/public_devnet_v1.checkpoints.jsonl"
CHECKPOINT_LOG_REL="mfn-node/testdata/public_devnet_v1.checkpoints.jsonl"
PLAYBOOK="docs/TESTNET_LAUNCH.md"
EVIDENCE_DIR="$SCRIPT_DIR/evidence"
JSON=0
[[ "${1:-}" == "--json" ]] && JSON=1

evidence_passes() {
  local pattern="$1"
  local f
  shopt -s nullglob
  for f in $EVIDENCE_DIR/$pattern; do
    if grep -q "SUMMARY: PASS" "$f" 2>/dev/null; then
      printf '%s\n' "$(basename "$f")"
      return 0
    fi
  done
  return 1
}

head_sha="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

genesis_id=""
seed_count=0
if [[ -f "$MANIFEST" ]]; then
  genesis_id="$(python3 -c "import json; print(json.load(open('$MANIFEST'))['genesis_id'])" 2>/dev/null || true)"
  seed_count="$(python3 -c "import json; print(len(json.load(open('$MANIFEST')).get('seed_nodes',[])))" 2>/dev/null || echo 0)"
fi

missing_bins=()
for b in mfnd mfn-cli mfn-storage-operator; do
  [[ -x "$REPO_ROOT/target/release/$b" ]] || missing_bins+=("$b")
done

tl5_evidence=0
tl6_evidence=0
tl5_file=""
tl6_file=""
if tl5_file="$(evidence_passes "vps-internet-soak-linux-*.txt" 2>/dev/null)"; then
  tl5_evidence=1
fi
if tl6_file="$(evidence_passes "vps-participant-rehearsal-*.txt" 2>/dev/null)"; then
  tl6_evidence=1
fi

local_mfer_no_observer=0
local_mfer_observer=0
local_mfer_no_observer_file=""
local_mfer_observer_file=""
if local_mfer_no_observer_file="$(evidence_passes "participant-rehearsal-no-observer-*.txt" 2>/dev/null)"; then
  local_mfer_no_observer=1
fi
if local_mfer_observer_file="$(evidence_passes "participant-rehearsal-observer-*.txt" 2>/dev/null)"; then
  local_mfer_observer=1
fi
local_rc_complete=0
if (( local_mfer_no_observer == 1 && local_mfer_observer == 1 )); then
  local_rc_complete=1
fi

release_evidence_archived=0
release_evidence_file=""
shopt -s nullglob
for f in "$EVIDENCE_DIR"/release-evidence-*.json; do
  release_evidence_archived=1
  release_evidence_file="$(basename "$f")"
  break
done

checkpoint_log_exists=0
checkpoint_log_entries=0
checkpoint_log_published=0
checkpoint_log_verified=""
if [[ -f "$CHECKPOINT_LOG" ]]; then
  checkpoint_log_exists=1
  checkpoint_log_entries="$(grep -c '[^[:space:]]' "$CHECKPOINT_LOG" 2>/dev/null || echo 0)"
  if (( checkpoint_log_entries > 0 )); then
    checkpoint_log_published=1
    mcli="$REPO_ROOT/target/release/mfn-cli"
    if [[ -x "$mcli" ]]; then
      if "$mcli" checkpoint-log verify "$CHECKPOINT_LOG" >/dev/null 2>&1; then
        checkpoint_log_verified=1
      else
        checkpoint_log_verified=0
      fi
    fi
  fi
fi

rc_audit_go=0
rc_audit_file=""
for f in "$EVIDENCE_DIR"/rc-audit-dry-run-*.json; do
  if python3 -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get('decision')=='go' else 1)" "$f" 2>/dev/null; then
    rc_audit_go=1
    rc_audit_file="$(basename "$f")"
    break
  fi
done

phase="TL-5 (provision VPS - see docs/VPS_PROVISION.md)"
next_action="docs/VPS_PROVISION.md then bash scripts/public-devnet-v1/vps-preflight.sh"
if [[ "$seed_count" -gt 0 ]]; then
  phase="TL-9+ (seed_nodes published - run launch-go-no-go.sh before invite)"
  next_action="bash scripts/public-devnet-v1/launch-go-no-go.sh"
elif (( tl6_evidence == 1 )); then
  phase="TL-7 (human genesis ceremony - TESTNET_GENESIS_CEREMONY.md)"
  if (( checkpoint_log_published == 0 )); then
    next_action="complete TL-7 sign-off then publish-seed-nodes.sh + publish-checkpoint-log.sh --apply"
  else
    next_action="complete TL-7 sign-off then publish-seed-nodes.sh (checkpoint log already has entries)"
  fi
elif (( tl5_evidence == 1 )); then
  phase="TL-6 (VPS soak done; run vps-participant-rehearsal.sh)"
  next_action="bash scripts/public-devnet-v1/vps-participant-rehearsal.sh --no-start --no-stop"
elif (( local_rc_complete == 1 )) && [[ ${#missing_bins[@]} -eq 0 ]]; then
  phase="TL-5 (local RC complete - provision VPS for internet soak)"
  next_action="bash scripts/public-devnet-v1/vps-execution-checklist.sh then docs/VPS_PROVISION.md -> vps-preflight.sh -> vps-internet-soak.sh"
elif [[ ${#missing_bins[@]} -eq 0 ]]; then
  phase="TL-5 (build complete - run local MFER rehearsals then provision VPS)"
  next_action="participant-rehearsal-smoke before VPS; see docs/VPS_PROVISION.md"
fi

internet="false"
[[ "$seed_count" -gt 0 ]] && internet="true"

ci_run="" ci_status="" ci_conclusion="" ci_head="" ci_msg="gh not available"
if command -v gh >/dev/null 2>&1; then
  if line="$(cd "$REPO_ROOT" && gh run list --workflow CI --limit 1 --json databaseId,status,conclusion,headSha 2>/dev/null)"; then
    ci_run="$(echo "$line" | python3 -c "import json,sys; r=json.load(sys.stdin)[0]; print(r['databaseId'])")"
    ci_status="$(echo "$line" | python3 -c "import json,sys; r=json.load(sys.stdin)[0]; print(r['status'])")"
    ci_conclusion="$(echo "$line" | python3 -c "import json,sys; r=json.load(sys.stdin)[0]; print(r.get('conclusion') or '')")"
    ci_head="$(echo "$line" | python3 -c "import json,sys; r=json.load(sys.stdin)[0]; print(r['headSha'][:7])")"
    ci_msg="run=$ci_run status=$ci_status conclusion=$ci_conclusion"
  fi
fi

if [[ "$JSON" -eq 1 ]]; then
  export REPO_ROOT PLAYBOOK phase head_sha genesis_id seed_count internet next_action
  export tl5_evidence tl6_evidence tl5_file tl6_file
  export local_mfer_no_observer local_mfer_observer local_rc_complete
  export local_mfer_no_observer_file local_mfer_observer_file
  export release_evidence_archived release_evidence_file rc_audit_go rc_audit_file
  export checkpoint_log_exists checkpoint_log_entries checkpoint_log_published checkpoint_log_verified
  export CHECKPOINT_LOG_REL ci_run ci_status ci_conclusion ci_msg
  python3 - <<'PY'
import json, os, pathlib

repo = pathlib.Path(os.environ["REPO_ROOT"])
missing = []
for b in ("mfnd", "mfn-cli", "mfn-storage-operator"):
    if not (repo / "target/release" / b).is_file():
        missing.append(b)

verified_raw = os.environ.get("checkpoint_log_verified", "")
verified = None
if verified_raw == "1":
    verified = True
elif verified_raw == "0":
    verified = False

print(json.dumps({
    "schema_version": "launch-status.v6",
    "lane": 7,
    "playbook": os.environ["PLAYBOOK"],
    "invite_packet": "docs/TESTNET_INVITE.md",
    "execution_checklist": {
        "schema_version": "vps-execution-checklist.v2",
        "helper": "bash scripts/public-devnet-v1/vps-execution-checklist.sh",
        "rehearsal": "bash scripts/public-devnet-v1/vps-execution-checklist-rehearsal-smoke.sh --plan-only",
    },
    "treasury_telemetry": {
        "schema_version": "treasury-telemetry-watch.v1",
        "helper": "bash scripts/public-devnet-v1/treasury-telemetry-watch.sh",
        "rehearsal": "bash scripts/public-devnet-v1/treasury-telemetry-watch.sh --plan-only",
        "revisit_doc": "docs/FEES.md#5-parameter-review-2026-07-should-fees-rise-and-should-the-tail-feed-the-treasury",
    },
    "role_templates": {
        "schema_version": "vps-role-templates.v1",
        "helper_doc": "docs/REFERENCE_TOPOLOGY.md",
        "rehearsal": "bash scripts/public-devnet-v1/vps-role-templates-rehearsal-smoke.sh --plan-only",
        "templates": [
            "scripts/public-devnet-v1/vps-role-validator.env.example",
            "scripts/public-devnet-v1/vps-role-observer.env.example",
            "scripts/public-devnet-v1/vps-role-operator.env.example",
            "scripts/public-devnet-v1/vps-role-wallet.env.example",
        ],
    },
    "suggested_phase": os.environ["phase"],
    "next_action": os.environ.get("next_action", ""),
    "head_sha": os.environ["head_sha"],
    "genesis_id": os.environ["genesis_id"],
    "seed_nodes_count": int(os.environ["seed_count"]),
    "internet_facing": os.environ["internet"] == "true",
    "local_rc_complete": os.environ.get("local_rc_complete") == "1",
    "local_mfer_rehearsal": {
        "no_observer": os.environ.get("local_mfer_no_observer") == "1",
        "observer": os.environ.get("local_mfer_observer") == "1",
        "no_observer_file": os.environ.get("local_mfer_no_observer_file", ""),
        "observer_file": os.environ.get("local_mfer_observer_file", ""),
    },
    "vps_soak_evidence": os.environ.get("tl5_evidence") == "1",
    "vps_rehearsal_evidence": os.environ.get("tl6_evidence") == "1",
    "vps_soak_file": os.environ.get("tl5_file", ""),
    "vps_rehearsal_file": os.environ.get("tl6_file", ""),
    "release_evidence_archived": os.environ.get("release_evidence_archived") == "1",
    "release_evidence_file": os.environ.get("release_evidence_file", ""),
    "rc_audit_go": os.environ.get("rc_audit_go") == "1",
    "rc_audit_file": os.environ.get("rc_audit_file", ""),
    "checkpoint_log": {
        "path": os.environ.get("CHECKPOINT_LOG_REL", ""),
        "exists": os.environ.get("checkpoint_log_exists") == "1",
        "entry_count": int(os.environ.get("checkpoint_log_entries", "0")),
        "published": os.environ.get("checkpoint_log_published") == "1",
        "verified": verified,
    },
    "release_binaries_missing": missing,
    "ci": {
        "message": os.environ["ci_msg"],
        "run_id": os.environ.get("ci_run", ""),
        "status": os.environ.get("ci_status", ""),
        "conclusion": os.environ.get("ci_conclusion", ""),
    },
}, indent=2))
PY
  exit 0
fi

echo "launch-status: lane=7 phase=$phase head=$head_sha"
echo "launch-status: genesis_id=$genesis_id seed_nodes=$seed_count internet_facing=$internet"
echo "launch-status: local_rc_complete=$([[ $local_rc_complete -eq 1 ]] && echo true || echo false) local_mfer_no_observer=$local_mfer_no_observer local_mfer_observer=$local_mfer_observer"
echo "launch-status: vps_soak_evidence=$([[ $tl5_evidence -eq 1 ]] && echo true || echo false) vps_rehearsal_evidence=$([[ $tl6_evidence -eq 1 ]] && echo true || echo false)"
echo "launch-status: release_evidence_archived=$([[ $release_evidence_archived -eq 1 ]] && echo true || echo false) rc_audit_go=$([[ $rc_audit_go -eq 1 ]] && echo true || echo false)"
echo "launch-status: checkpoint_log_entries=$checkpoint_log_entries published=$([[ $checkpoint_log_published -eq 1 ]] && echo true || echo false) verified=${checkpoint_log_verified:-unknown}"
if [[ ${#missing_bins[@]} -gt 0 ]]; then
  echo "launch-status: missing_release_binaries=${missing_bins[*]}"
fi
echo "launch-status: ci $ci_msg"
echo "launch-status: next_action=$next_action"
echo "launch-status: playbook=$PLAYBOOK invite=docs/TESTNET_INVITE.md"
