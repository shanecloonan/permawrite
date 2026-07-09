#!/usr/bin/env bash
# Lane 7 — read-only checklist before TL-5/TL-6 VPS execution (laptop or VPS).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
JSON=0
STRICT=0

usage() {
  cat <<'EOF'
usage: vps-execution-checklist.sh [--json] [--strict]

Read-only gate summary before internet-facing TL-5 soak and TL-6 rehearsal.
Does not start mesh processes or require vps-bind.env.

  --json     machine-readable report
  --strict   exit 1 unless local_rc_complete and latest CI success (when gh available)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) JSON=1; shift ;;
    --strict) STRICT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "vps-execution-checklist: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

launch_json="$(bash "$SCRIPT_DIR/launch-status.sh" --json)"
export LAUNCH_JSON="$launch_json"
export REPO_ROOT
export STRICT_FLAG="$STRICT"

report="$(python3 - <<'PY'
import json, os, subprocess

launch = json.loads(os.environ["LAUNCH_JSON"])
repo = os.environ["REPO_ROOT"]
strict = os.environ.get("STRICT_FLAG") == "1"

def gh_ci():
    try:
        out = subprocess.check_output(
            [
                "gh", "run", "list", "--workflow", "CI", "--limit", "1",
                "--json", "databaseId,status,conclusion,headSha",
            ],
            cwd=repo,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        runs = json.loads(out)
        return runs[0] if runs else {}
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
        return {}

ci = gh_ci()
ci_green = ci.get("status") == "completed" and ci.get("conclusion") == "success"

blockers = []
warnings = []
if not launch.get("local_rc_complete"):
    blockers.append("local MFER rehearsals incomplete (need no-observer + observer PASS evidence)")
if not launch.get("release_evidence_archived"):
    warnings.append("release-evidence-*.json not archived under evidence/ (refresh on green CI head)")
if not launch.get("rc_audit_go"):
    warnings.append("rc-audit-dry-run go evidence missing under evidence/")
if launch.get("vps_soak_evidence"):
    warnings.append("TL-5 VPS soak evidence already present — skip re-soak unless reprovisioning")
if launch.get("vps_rehearsal_evidence"):
    warnings.append("TL-6 VPS rehearsal evidence already present")
if ci and not ci_green:
    msg = (
        f"GitHub CI not green (run={ci.get('databaseId')} "
        f"status={ci.get('status')} conclusion={ci.get('conclusion')})"
    )
    if strict:
        blockers.append(msg)
    else:
        warnings.append(msg)
elif not ci:
    warnings.append("gh not available — skip live CI lookup")

print(json.dumps({
    "schema_version": "vps-execution-checklist.v1",
    "ready_for_vps_execution": len(blockers) == 0,
    "local_rc_complete": launch.get("local_rc_complete", False),
    "suggested_phase": launch.get("suggested_phase", ""),
    "head_sha": launch.get("head_sha", ""),
    "genesis_id": launch.get("genesis_id", ""),
    "blockers": blockers,
    "warnings": warnings,
    "launch_status": launch,
    "ci": ci,
    "commands": {
        "provision": "docs/VPS_PROVISION.md",
        "preflight": "bash scripts/public-devnet-v1/vps-preflight.sh",
        "tl5_soak": "bash scripts/public-devnet-v1/vps-internet-soak.sh",
        "tl6_rehearsal": "bash scripts/public-devnet-v1/vps-participant-rehearsal.sh --no-start --no-stop",
        "archive": "git add scripts/public-devnet-v1/evidence/vps-*.txt && git commit",
        "ceremony": "bash scripts/public-devnet-v1/vps-launch-ceremony.sh",
    },
}, indent=2))
PY
)"

if [[ "$JSON" -eq 1 ]]; then
  echo "$report"
else
  export REPORT_JSON="$report"
  python3 - <<'PY'
import json, os

doc = json.loads(os.environ["REPORT_JSON"])
print(f"vps-execution-checklist: ready={doc['ready_for_vps_execution']} head={doc['head_sha']}")
print(f"vps-execution-checklist: phase={doc['suggested_phase']}")
print(f"vps-execution-checklist: local_rc_complete={doc['local_rc_complete']}")
for b in doc.get("blockers", []):
    print(f"vps-execution-checklist: BLOCKER {b}")
for w in doc.get("warnings", []):
    print(f"vps-execution-checklist: WARN {w}")
print("vps-execution-checklist: ordered path:")
cmds = doc["commands"]
print(f"  1. {cmds['provision']}")
print(f"  2. {cmds['preflight']}")
print(f"  3. {cmds['tl5_soak']}  # archive vps-internet-soak-linux-*.txt")
print(f"  4. {cmds['tl6_rehearsal']}  # archive vps-participant-rehearsal-*.txt")
print(f"  5. {cmds['archive']}")
print(f"  6. {cmds['ceremony']}")
PY
fi

ready="$(python3 -c "import json,sys; print('1' if json.loads(sys.argv[1])['ready_for_vps_execution'] else '0')" "$report")"
if [[ "$ready" != "1" ]]; then
  exit 1
fi
exit 0
