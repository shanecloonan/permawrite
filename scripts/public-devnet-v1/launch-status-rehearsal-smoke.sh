#!/usr/bin/env bash
# Lane 7: plan-only launch-status v9 schema rehearsal.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates launch-status.v9 JSON schema + checkpoint_log + execution_checklist (no VPS required).
EOF
}

PLAN_ONLY=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(basename "$0"): unknown argument $1" >&2; exit 1 ;;
  esac
done

json="$(bash "$SCRIPT_DIR/launch-status.sh" --json)"
export JSON="$json"
python3 - <<'PY'
import json, os, sys
doc = json.loads(os.environ["JSON"])
assert doc.get("schema_version") == "launch-status.v9", doc.get("schema_version")
cl = doc.get("checkpoint_log") or {}
assert cl.get("path") == "mfn-node/testdata/public_devnet_v1.checkpoints.jsonl", cl.get("path")
for key in ("exists", "entry_count", "published"):
    assert key in cl, key
ec = doc.get("execution_checklist") or {}
assert ec.get("schema_version") == "vps-execution-checklist.v2", ec.get("schema_version")
assert "vps-execution-checklist.sh" in ec.get("helper", ""), ec.get("helper")
tt = doc.get("treasury_telemetry") or {}
assert tt.get("schema_version") == "treasury-telemetry-watch.v1", tt.get("schema_version")
assert "treasury-telemetry-watch.sh" in tt.get("helper", ""), tt.get("helper")
rt = doc.get("role_templates") or {}
assert rt.get("schema_version") == "vps-role-templates.v1", rt.get("schema_version")
assert len(rt.get("templates") or []) >= 4, rt.get("templates")
sr = doc.get("software_ready") or {}
assert sr.get("schema_version") == "software-ready-pin.v1", sr.get("schema_version")
assert sr.get("release_commit"), sr
fp = doc.get("fraud_proof") or {}
assert fp.get("phase_shipped") == "1c", fp.get("phase_shipped")
assert fp.get("on_chain_producer_slash") == "shipped", fp.get("on_chain_producer_slash")
assert fp.get("list_fraud_contests_rpc") is True, fp.get("list_fraud_contests_rpc")
assert fp.get("validity_proof") == "research", fp.get("validity_proof")
assert fp.get("validity_proof_phase") == "4b", fp.get("validity_proof_phase")
assert fp.get("stark_backend") == "digest-stub", fp.get("stark_backend")
assert fp.get("p2p_tag_validity") == "0x14", fp.get("p2p_tag_validity")
print("launch-status-rehearsal-smoke: plan")
print("  schema=launch-status.v9")
print(f"  checkpoint_log.path={cl.get('path')}")
print(f"  checkpoint_log.entry_count={cl.get('entry_count')}")
print(f"  execution_checklist={ec.get('schema_version')}")
print(f"  treasury_telemetry={tt.get('schema_version')}")
print(f"  role_templates={rt.get('schema_version')}")
print(f"  software_ready_pin={sr.get('release_commit')} head_matches_pin={sr.get('head_matches_pin')}")
print(f"  fraud_proof_phase={fp.get('phase_shipped')}")
print(f"  validity_proof={fp.get('validity_proof')}")
print("  helper=launch-status.sh --json")
PY

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "launch-status-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "launch-status-rehearsal-smoke: live mode not implemented" >&2
exit 1
