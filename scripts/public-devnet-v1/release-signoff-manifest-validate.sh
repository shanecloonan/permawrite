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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
python3 - "$manifest" "$REPO_ROOT" <<'PY'
import json
import os
import sys

manifest_path = sys.argv[1]
repo_root = sys.argv[2]
with open(manifest_path, "r", encoding="utf-8-sig") as handle:
    doc = json.load(handle)

issues = []


def issue(message):
    issues.append(message)


def is_toy_seed(value):
    text = "".join(str(value or "").split()).lower()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) < 32 or len(text) % 2:
        return True
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return True
    return len(set(raw)) <= 1


def genesis_has_toy_keys(genesis):
    seeds = []
    for op in genesis.get("storage_operators") or []:
        seeds.append((op or {}).get("payout_seed_hex"))
    for val in genesis.get("validators") or []:
        seeds.append((val or {}).get("vrf_seed_hex"))
        seeds.append((val or {}).get("bls_seed_hex"))
    return (not seeds) or any(is_toy_seed(seed) for seed in seeds)


def genesis_economy(evidence_doc):
    rel = ((evidence_doc.get("economy") or {}).get("genesis_path") or "").strip()
    candidates = [rel, os.path.join(repo_root, rel)] if rel else []
    genesis_path = next((candidate for candidate in candidates if candidate and os.path.isfile(candidate)), None)
    if not genesis_path:
        return None
    with open(genesis_path, "r", encoding="utf-8-sig") as handle:
        genesis = json.load(handle)
    emission = genesis.get("emission") or {}
    endowment = genesis.get("endowment") or {}
    try:
        subsidy_bps = int(emission.get("subsidy_to_treasury_bps") or 0)
        bond_atoms = int(endowment.get("min_storage_operator_bond") or 0)
    except (TypeError, ValueError):
        subsidy_bps = 0
        bond_atoms = 0
    bonded = 0
    if bond_atoms > 0:
        for op in genesis.get("storage_operators") or []:
            try:
                amount = int((op or {}).get("bond_amount") or 0)
            except (TypeError, ValueError):
                amount = 0
            if amount >= bond_atoms:
                bonded += 1
    return {
        "subsidy_to_treasury_bps": subsidy_bps,
        "min_storage_operator_bond": bond_atoms,
        "path_a_experimental": subsidy_bps == 0 or bond_atoms == 0,
        "bonded_operators": bonded,
        "path_a_toy_keys": genesis_has_toy_keys(genesis),
    }


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
    evidence_rel = release_evidence.get("path") if isinstance(release_evidence, dict) else ""
    evidence_path = None
    if evidence_rel:
        candidates = [
            evidence_rel,
            os.path.join(repo_root, evidence_rel),
            os.path.join(os.path.dirname(os.path.abspath(manifest_path)), evidence_rel),
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                evidence_path = candidate
                break
    if not evidence_path:
        issue("go decision requires readable release evidence")
    else:
        with open(evidence_path, "r", encoding="utf-8-sig") as handle:
            evidence = json.load(handle)
        genesis = genesis_economy(evidence)
        if genesis is None:
            issue("go decision requires readable genesis at economy.genesis_path")
        elif genesis["subsidy_to_treasury_bps"] <= 0 or genesis["min_storage_operator_bond"] <= 0 or genesis["path_a_experimental"]:
            issue("go decision requires funded genesis economy (subsidy>0, bond>0, path_a_experimental=false)")
        elif genesis["bonded_operators"] < 2:
            issue("go decision requires >=2 genesis storage_operators bonded at min_storage_operator_bond")
        elif genesis["path_a_toy_keys"]:
            issue("go decision requires genesis operator/validator seeds that are not repeating-byte toy keys")
        evidence_ci = evidence.get("ci") or {}
        if evidence_ci.get("status") != "completed" or evidence_ci.get("conclusion") != "success":
            issue("go decision requires completed successful CI on bound evidence")
        nightly = evidence.get("nightly") or {}
        if nightly.get("status") != "completed" or nightly.get("conclusion") != "success":
            issue("go decision requires completed successful Nightly on bound evidence")

if issues:
    for message in issues:
        print(f"release-signoff-manifest-validate: {message}", file=sys.stderr)
    sys.exit(1)

print("release-signoff-manifest-validate: OK")
PY
