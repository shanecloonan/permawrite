#!/usr/bin/env bash
# Lane 7: plan-only vps-execution-checklist rehearsal (TL-5/TL-6 preflight gate).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOC="$REPO_ROOT/docs/VPS_PROVISION.md"
OPS="$REPO_ROOT/scripts/public-devnet-v1/OPERATORS.md"

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates vps-execution-checklist v1 JSON schema + OPERATORS cross-links (no VPS).
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

for f in "$DOC" "$OPS"; do
  if [[ ! -f "$f" ]]; then
    echo "vps-execution-checklist-rehearsal-smoke: missing $f" >&2
    exit 1
  fi
done

if ! grep -qF -- "vps-execution-checklist" "$OPS"; then
  echo "vps-execution-checklist-rehearsal-smoke: OPERATORS.md missing vps-execution-checklist" >&2
  exit 1
fi

json="$(bash "$SCRIPT_DIR/vps-execution-checklist.sh" --json)"
export JSON="$json"
python3 - <<'PY'
import json, os, sys
doc = json.loads(os.environ["JSON"])
assert doc.get("schema_version") == "vps-execution-checklist.v1", doc.get("schema_version")
cmds = doc.get("commands") or {}
for key in ("provision", "preflight", "tl5_soak", "tl6_rehearsal", "treasury_telemetry", "pm23_rehearsal"):
    assert key in cmds, key
assert "launch_status" in doc, "launch_status missing"
print("vps-execution-checklist-rehearsal-smoke: plan")
print(f"  schema={doc.get('schema_version')}")
print(f"  ready_for_vps_execution={doc.get('ready_for_vps_execution')}")
print(f"  local_rc_complete={doc.get('local_rc_complete')}")
print("  helper=vps-execution-checklist.sh --json [--strict]")
PY

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "vps-execution-checklist-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "vps-execution-checklist-rehearsal-smoke: live mode not implemented" >&2
exit 1
