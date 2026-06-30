#!/usr/bin/env bash
# Validate a release-signoff-manifest.v1 JSON decision record.
set -euo pipefail

manifest=""

usage() {
  cat <<'EOF'
usage: release-signoff-manifest-validate.sh --manifest FILE
EOF
}

while (($# > 0)); do
  case "$1" in
    --manifest)
      manifest="${2:?missing value for --manifest}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "release-signoff-manifest-validate: unknown argument $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$manifest" ]]; then
  echo "release-signoff-manifest-validate: --manifest is required" >&2
  exit 2
fi
if [[ ! -f "$manifest" ]]; then
  echo "release-signoff-manifest-validate: missing file $manifest" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "release-signoff-manifest-validate: python3 is required" >&2
  exit 127
fi

python3 - "$manifest" <<'PY'
import json
import sys

manifest_path = sys.argv[1]
with open(manifest_path, "r", encoding="utf-8-sig") as handle:
    doc = json.load(handle)

issues = []


def issue(message):
    issues.append(message)


def require_string(obj, key, path):
    if not isinstance(obj, dict) or not isinstance(obj.get(key), str) or not obj.get(key):
        issue(f"{path}.{key} is required")


def require_bool(obj, key, path):
    if not isinstance(obj, dict) or not isinstance(obj.get(key), bool):
        issue(f"{path}.{key} must be boolean")


def validate_gate(gate, path):
    if not isinstance(gate, dict):
        issue(f"{path} is required")
        return
    require_string(gate, "path", path)
    require_string(gate, "message", path)
    if gate.get("status") not in ("pass", "fail", "not provided"):
        issue(f"{path}.status must be pass, fail, or not provided")


if doc.get("schema_version") != "release-signoff-manifest.v1":
    issue("schema_version must be release-signoff-manifest.v1")
if doc.get("decision") not in ("go", "no-go"):
    issue("decision must be go or no-go")
require_string(doc, "generated_utc", "manifest")
require_string(doc, "commit", "manifest")

release_evidence = doc.get("release_evidence")
if not isinstance(release_evidence, dict):
    issue("release_evidence is required")
else:
    require_string(release_evidence, "path", "release_evidence")
    require_string(release_evidence, "commit", "release_evidence")
    if release_evidence.get("schema_version") != "release-evidence.v1":
        issue("release_evidence.schema_version must be release-evidence.v1")
    if doc.get("commit") and release_evidence.get("commit") and doc.get("commit") != release_evidence.get("commit"):
        issue("release_evidence.commit must match manifest commit")

gates = doc.get("gates")
if not isinstance(gates, dict):
    issue("gates is required")
    gates = {}
validate_gate(gates.get("archive_validation"), "gates.archive_validation")
validate_gate(gates.get("artifact_inventory"), "gates.artifact_inventory")

approvals = doc.get("approvals")
required_approvals = (
    "threat_model_reviewed",
    "residual_risks_have_named_owners",
    "rpc_exposure_approved",
    "backups_and_restore_rehearsed",
    "halt_rollback_authority_agreed",
)
if not isinstance(approvals, dict):
    issue("approvals is required")
    approvals = {}
else:
    require_string(approvals, "operator", "approvals")
    require_string(approvals, "reviewer", "approvals")
    require_string(approvals, "notes", "approvals")
    for key in required_approvals:
        require_bool(approvals, key, "approvals")

manifest_issues = doc.get("issues")
if not isinstance(manifest_issues, list) or not all(isinstance(item, str) for item in manifest_issues):
    issue("issues array is required")
    manifest_issues = []

if doc.get("decision") == "go":
    ci = gates.get("ci")
    if not isinstance(ci, dict) or ci.get("status") != "completed" or ci.get("conclusion") != "success":
        issue("go decision requires completed successful CI")
    if not isinstance(gates.get("archive_validation"), dict) or gates["archive_validation"].get("status") != "pass":
        issue("go decision requires passing archive validation")
    if not isinstance(gates.get("artifact_inventory"), dict) or gates["artifact_inventory"].get("status") != "pass":
        issue("go decision requires passing artifact inventory validation")
    if manifest_issues:
        issue("go decision requires empty issues")
    for key in required_approvals:
        if approvals.get(key) is not True:
            issue(f"go decision requires approval '{key}'")

if issues:
    for message in issues:
        print(f"release-signoff-manifest-validate: {message}", file=sys.stderr)
    sys.exit(1)

print("release-signoff-manifest-validate: OK")
PY
