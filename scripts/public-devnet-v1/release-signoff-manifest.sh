#!/usr/bin/env bash
# Build a machine-readable release-candidate sign-off decision manifest.
set -euo pipefail

release_evidence_json=""
archive_dir=""
inventory=""
ci_mock_runs=""
commit=""
decision="no-go"
operator=""
reviewer=""
notes=""
output_path=""
allow_dry_run=0
threat_model_reviewed=0
residual_risks_have_owners=0
rpc_exposure_approved=0
backups_restore_rehearsed=0
halt_rollback_authority_agreed=0

usage() {
  cat <<'EOF'
usage: release-signoff-manifest.sh --release-evidence-json FILE [options]

Options:
  --release-evidence-json FILE  release-evidence.v1 JSON to bind into the manifest.
  --archive-dir DIR             Staged release archive to validate.
  --inventory FILE              Filled artifact inventory to validate.
  --ci-mock-runs FILE           Mock GitHub run JSON for CI/offline tests.
  --commit SHA                  Exact release commit. Defaults to release evidence commit or HEAD.
  --decision go|no-go           Final decision. Defaults to no-go.
  --operator NAME               Release operator name or handle.
  --reviewer NAME               Independent reviewer name or handle.
  --notes TEXT                  Free-form sign-off notes.
  --output FILE                 Write JSON manifest to FILE.
  --allow-dry-run               Allow dry-run archive evidence/template artifacts.
  --threat-model-reviewed       Required for --decision go.
  --residual-risks-have-owners  Required for --decision go.
  --rpc-exposure-approved       Required for --decision go.
  --backups-restore-rehearsed   Required for --decision go.
  --halt-rollback-authority-agreed
                                Required for --decision go.
EOF
}

while (($# > 0)); do
  case "$1" in
    --release-evidence-json) release_evidence_json="${2:?missing value for --release-evidence-json}"; shift 2 ;;
    --archive-dir) archive_dir="${2:?missing value for --archive-dir}"; shift 2 ;;
    --inventory) inventory="${2:?missing value for --inventory}"; shift 2 ;;
    --ci-mock-runs) ci_mock_runs="${2:?missing value for --ci-mock-runs}"; shift 2 ;;
    --commit) commit="${2:?missing value for --commit}"; shift 2 ;;
    --decision) decision="${2:?missing value for --decision}"; shift 2 ;;
    --operator) operator="${2:?missing value for --operator}"; shift 2 ;;
    --reviewer) reviewer="${2:?missing value for --reviewer}"; shift 2 ;;
    --notes) notes="${2:?missing value for --notes}"; shift 2 ;;
    --output) output_path="${2:?missing value for --output}"; shift 2 ;;
    --allow-dry-run) allow_dry_run=1; shift ;;
    --threat-model-reviewed) threat_model_reviewed=1; shift ;;
    --residual-risks-have-owners) residual_risks_have_owners=1; shift ;;
    --rpc-exposure-approved) rpc_exposure_approved=1; shift ;;
    --backups-restore-rehearsed) backups_restore_rehearsed=1; shift ;;
    --halt-rollback-authority-agreed) halt_rollback_authority_agreed=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "release-signoff-manifest: unknown argument $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$release_evidence_json" ]]; then
  echo "release-signoff-manifest: --release-evidence-json is required" >&2
  exit 2
fi
if [[ "$decision" != "go" && "$decision" != "no-go" ]]; then
  echo "release-signoff-manifest: --decision must be go or no-go" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "release-signoff-manifest: python3 is required" >&2
  exit 127
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

python3 - "$REPO_ROOT" "$release_evidence_json" "$archive_dir" "$inventory" "$ci_mock_runs" "$commit" "$decision" "$operator" "$reviewer" "$notes" "$output_path" "$allow_dry_run" "$threat_model_reviewed" "$residual_risks_have_owners" "$rpc_exposure_approved" "$backups_restore_rehearsed" "$halt_rollback_authority_agreed" <<'PY'
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

(
    repo_root,
    release_evidence_json,
    archive_dir,
    inventory,
    ci_mock_runs,
    commit,
    decision,
    operator,
    reviewer,
    notes,
    output_path,
    allow_dry_run,
    threat_model_reviewed,
    residual_risks_have_owners,
    rpc_exposure_approved,
    backups_restore_rehearsed,
    halt_rollback_authority_agreed,
) = sys.argv[1:]

script_dir = os.path.join(repo_root, "scripts", "public-devnet-v1")
issues = []


def add_issue(message):
    issues.append(message)


def run_tool(args):
    proc = subprocess.run(args, cwd=repo_root, text=True, capture_output=True)
    return {"exit_code": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}


def git_head():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root, text=True).strip()
    except Exception:
        return ""


with open(release_evidence_json, "r", encoding="utf-8-sig") as handle:
    evidence = json.load(handle)

if evidence.get("schema_version") != "release-evidence.v1":
    add_issue("release evidence schema_version is not release-evidence.v1")

if not commit:
    commit = (evidence.get("commit") or {}).get("head") or git_head()
if (evidence.get("commit") or {}).get("head") and (evidence.get("commit") or {}).get("head") != commit:
    add_issue("release evidence commit does not match requested commit")

ci_args = ["bash", os.path.join(script_dir, "release-ci-watch.sh"), "--commit", commit, "--json"]
if ci_mock_runs:
    ci_args.extend(["--mock-runs", ci_mock_runs])
ci_result = run_tool(ci_args)
ci_object = None
if ci_result["stdout"]:
    try:
        ci_object = json.loads(ci_result["stdout"])
    except Exception:
        add_issue("release-ci-watch JSON output could not be parsed")
if ci_result["exit_code"] != 0:
    add_issue("GitHub CI is not green for the exact commit")

archive_status = "not provided"
archive_message = ""
if archive_dir:
    archive_args = ["bash", os.path.join(script_dir, "release-archive-validate.sh"), "--archive-dir", archive_dir]
    if allow_dry_run == "1":
        archive_args.append("--allow-dry-run")
    archive_result = run_tool(archive_args)
    archive_status = "pass" if archive_result["exit_code"] == 0 else "fail"
    archive_message = archive_result["stdout"] if archive_result["exit_code"] == 0 else archive_result["stderr"]
    if archive_result["exit_code"] != 0:
        add_issue("release archive validation failed")

inventory_status = "not provided"
inventory_message = ""
if inventory:
    inventory_result = run_tool(["bash", os.path.join(script_dir, "artifact-inventory-validate.sh"), inventory])
    inventory_status = "pass" if inventory_result["exit_code"] == 0 else "fail"
    inventory_message = inventory_result["stdout"] if inventory_result["exit_code"] == 0 else inventory_result["stderr"]
    if inventory_result["exit_code"] != 0:
        add_issue("artifact inventory validation failed")

approvals = {
    "operator": operator,
    "reviewer": reviewer,
    "threat_model_reviewed": threat_model_reviewed == "1",
    "residual_risks_have_named_owners": residual_risks_have_owners == "1",
    "rpc_exposure_approved": rpc_exposure_approved == "1",
    "backups_and_restore_rehearsed": backups_restore_rehearsed == "1",
    "halt_rollback_authority_agreed": halt_rollback_authority_agreed == "1",
    "notes": notes,
}

if decision == "go":
    if not operator:
        add_issue("operator is required for go decision")
    if not reviewer:
        add_issue("reviewer is required for go decision")
    for key, value in approvals.items():
        if key in ("operator", "reviewer", "notes"):
            continue
        if not value:
            add_issue(f"approval '{key}' is required for go decision")
    if not archive_dir:
        add_issue("archive validation is required for go decision")
    if not inventory:
        add_issue("artifact inventory validation is required for go decision")

manifest = {
    "schema_version": "release-signoff-manifest.v1",
    "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "decision": decision,
    "commit": commit,
    "release_evidence": {
        "path": release_evidence_json,
        "schema_version": evidence.get("schema_version", ""),
        "commit": (evidence.get("commit") or {}).get("head", ""),
    },
    "gates": {
        "ci": ci_object,
        "archive_validation": {"status": archive_status, "path": archive_dir, "message": archive_message},
        "artifact_inventory": {"status": inventory_status, "path": inventory, "message": inventory_message},
    },
    "approvals": approvals,
    "issues": issues,
}

text = json.dumps(manifest, indent=2)
if output_path:
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(text + "\n")
    print(f"release-signoff-manifest: wrote {output_path}")
else:
    print(text)

if decision == "go" and issues:
    sys.exit(1)
PY
