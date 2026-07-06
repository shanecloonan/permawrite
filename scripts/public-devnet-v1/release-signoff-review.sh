#!/usr/bin/env bash
# Print a release sign-off checklist from a generated support bundle.
set -euo pipefail

BUNDLE_DIR=""
LAUNCH_NOTES="release-evidence.md"

usage() {
  cat <<'EOF'
usage: release-signoff-review.sh --bundle-dir DIR [--launch-notes FILE]

Prints a Markdown release sign-off checklist with concrete paths and detected
status from a generated public-devnet support bundle. Human approvals remain
unchecked by design.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      BUNDLE_DIR="${2:-}"
      shift 2
      ;;
    --launch-notes)
      LAUNCH_NOTES="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "release-signoff-review: unknown argument $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$BUNDLE_DIR" ]]; then
  echo "release-signoff-review: --bundle-dir is required" >&2
  exit 1
fi

python3 - "$BUNDLE_DIR" "$LAUNCH_NOTES" <<'PY'
import datetime
import json
import os
import sys

bundle = os.path.abspath(sys.argv[1])
launch_notes = sys.argv[2]
manifest_path = os.path.join(bundle, "manifest.json")
if not os.path.exists(manifest_path):
    raise SystemExit(f"release-signoff-review: missing manifest.json in {bundle}")

with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

release_evidence = manifest.get("release_evidence") or {}
evidence_file = release_evidence.get("copied_file") or "release-evidence.json"
evidence_path = os.path.join(bundle, evidence_file)
evidence = None
if os.path.exists(evidence_path):
    with open(evidence_path, "r", encoding="utf-8") as handle:
        evidence = json.load(handle)

def checked(ok: bool) -> str:
    return "x" if ok else " "

def line(ok: bool, text: str) -> str:
    return f"- [{checked(ok)}] {text}"

def has_file(name: str) -> bool:
    return os.path.exists(os.path.join(bundle, name))

schema = evidence.get("schema_version") if isinstance(evidence, dict) else None
evidence_commit = ((evidence or {}).get("commit") or {}).get("head")
manifest_commit = release_evidence.get("commit_head")
evidence_valid = bool(evidence) and schema == "release-evidence.v1"
manifest_evidence_valid = bool(release_evidence.get("provided")) and bool(release_evidence.get("valid"))
commit_matches = bool(evidence_commit and manifest_commit and evidence_commit == manifest_commit)
commands = manifest.get("commands") or []
failed_commands = [cmd for cmd in commands if cmd.get("exit_code") not in (0, None)]
core_files = ["node-status.json", "uploads-list.json", "operator-pool.json"]
support_files = [
    "wallet-status.json",
    "wallet-backup-info.json",
    "uploads-status.json",
    "operator-artifacts.json",
    "operator-challenge.json",
    "operator-inbox-status.json",
]
present_support = [name for name in support_files if has_file(name)]
rpc_endpoint = ((evidence or {}).get("rpc") or {}).get("endpoint")

now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
print("# Permawrite Release Sign-Off Bundle Review")
print()
print(f"Bundle: `{bundle}`")
print(f"Generated UTC: `{now}`")
print()
print("## Required Files")
print()
print(line(False, f"Launch notes include `{launch_notes}` for human review (outside support bundle)."))
print(line(evidence_valid, f"`{evidence_path}` exists and uses `schema_version=release-evidence.v1`."))
print(line(manifest_evidence_valid and commit_matches, f"`{manifest_path}` records valid release evidence and matches the evidence commit."))
for file_name in core_files:
    print(line(has_file(file_name), f"`{os.path.join(bundle, file_name)}` is present."))
print(line(len(failed_commands) == 0, "`manifest.json` has no unexplained command failures."))
print(line(len(present_support) > 0, "Wallet/storage support diagnostics are present when the launch claim depends on them."))
print()
print("## Required Approvals")
print()
print(line(False, "Release operator confirms commit, stats timestamp, GitHub CI, ignored/nightly smoke, and local CI mirror."))
print(line(False, "Security reviewer confirms pre-audit risk language and named owners for residual risks."))
print(line(False, "RPC/network reviewer confirms RPC exposure controls, P2P reachability, and expected genesis."))
print(line(False, "Storage/permanence reviewer confirms upload, replication/backfill, retrieval, and SPoRA proof rehearsal."))
print(line(False, "Operations reviewer confirms backups, restore rehearsal, rollback/halt authority, incident notes, and watchers."))
print()
print("## Detected Status")
print()
print(f"- Evidence schema: `{schema or 'missing'}`")
print(f"- Evidence commit: `{evidence_commit or 'missing'}`")
print(f"- Manifest evidence commit: `{manifest_commit or 'missing'}`")
print(f"- RPC endpoint: `{rpc_endpoint or 'missing'}`")
print(f"- Present wallet/storage files: `{', '.join(present_support) if present_support else 'none'}`")
failure_text = ", ".join(f"{cmd.get('name')}={cmd.get('exit_code')}" for cmd in failed_commands) or "none"
print(f"- Command failures: `{failure_text}`")
print()
print("Any unchecked required file, approval, unknown evidence field, dirty working tree, or unexplained command failure remains a no-go until a reviewer writes down the exception and names an owner.")
PY
