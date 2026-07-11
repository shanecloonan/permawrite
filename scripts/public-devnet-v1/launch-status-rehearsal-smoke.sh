#!/usr/bin/env bash
# Lane 7: plan-only launch-status v5 schema rehearsal.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates launch-status.v5 JSON schema + checkpoint_log + execution_checklist (no VPS required).
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
assert doc.get("schema_version") == "launch-status.v5", doc.get("schema_version")
cl = doc.get("checkpoint_log") or {}
assert cl.get("path") == "mfn-node/testdata/public_devnet_v1.checkpoints.jsonl", cl.get("path")
for key in ("exists", "entry_count", "published"):
    assert key in cl, key
ec = doc.get("execution_checklist") or {}
assert ec.get("schema_version") == "vps-execution-checklist.v2", ec.get("schema_version")
assert "vps-execution-checklist.sh" in ec.get("helper", ""), ec.get("helper")
print("launch-status-rehearsal-smoke: plan")
print("  schema=launch-status.v5")
print(f"  checkpoint_log.path={cl.get('path')}")
print(f"  checkpoint_log.entry_count={cl.get('entry_count')}")
print(f"  execution_checklist={ec.get('schema_version')}")
print("  helper=launch-status.sh --json")
PY

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "launch-status-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "launch-status-rehearsal-smoke: live mode not implemented" >&2
exit 1
