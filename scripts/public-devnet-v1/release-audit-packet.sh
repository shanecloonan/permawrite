#!/usr/bin/env bash
# Build a final release-candidate audit packet from all machine-readable gates.
set -euo pipefail

release_evidence_json=""
signoff_manifest=""
archive_dir=""
inventory=""
commit=""
ci_mock_runs=""
output_path=""
allow_dry_run=0
strict_stats_freshness=0
json_output=0

usage() {
  cat <<'EOF'
usage: release-audit-packet.sh --release-evidence-json FILE --signoff-manifest FILE --archive-dir DIR --inventory FILE [options]

Options:
  --commit SHA                 Exact release commit. Defaults to release evidence commit or HEAD.
  --ci-mock-runs FILE          Mock GitHub run JSON for CI/offline tests.
  --output FILE                Write the audit packet to FILE.
  --allow-dry-run              Allow dry-run archive evidence/template artifacts.
  --strict-stats-freshness     Compare CODEBASE_STATS.md to codebase-stats --dry-run output.
  --json                       Emit release-audit-packet.v1 JSON instead of Markdown text.
EOF
}

while (($# > 0)); do
  case "$1" in
    --release-evidence-json) release_evidence_json="${2:?missing value for --release-evidence-json}"; shift 2 ;;
    --signoff-manifest) signoff_manifest="${2:?missing value for --signoff-manifest}"; shift 2 ;;
    --archive-dir) archive_dir="${2:?missing value for --archive-dir}"; shift 2 ;;
    --inventory) inventory="${2:?missing value for --inventory}"; shift 2 ;;
    --commit) commit="${2:?missing value for --commit}"; shift 2 ;;
    --ci-mock-runs) ci_mock_runs="${2:?missing value for --ci-mock-runs}"; shift 2 ;;
    --output) output_path="${2:?missing value for --output}"; shift 2 ;;
    --allow-dry-run) allow_dry_run=1; shift ;;
    --strict-stats-freshness) strict_stats_freshness=1; shift ;;
    --json) json_output=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "release-audit-packet: unknown argument $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$release_evidence_json" || -z "$signoff_manifest" || -z "$archive_dir" || -z "$inventory" ]]; then
  echo "release-audit-packet: evidence, signoff manifest, archive dir, and inventory are required" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "release-audit-packet: python3 is required" >&2
  exit 127
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

python3 - "$REPO_ROOT" "$release_evidence_json" "$signoff_manifest" "$archive_dir" "$inventory" "$commit" "$ci_mock_runs" "$output_path" "$allow_dry_run" "$strict_stats_freshness" "$json_output" <<'PY'
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

(
    repo_root,
    release_evidence_json,
    signoff_manifest,
    archive_dir,
    inventory,
    commit,
    ci_mock_runs,
    output_path,
    allow_dry_run,
    strict_stats_freshness,
    json_output,
) = sys.argv[1:]

script_dir = os.path.join(repo_root, "scripts", "public-devnet-v1")
checks = []


def require_path(path, kind):
    full = os.path.join(repo_root, path) if not os.path.isabs(path) else path
    if kind == "dir" and not os.path.isdir(full):
        raise SystemExit(f"release-audit-packet: missing directory {path}")
    if kind == "file" and not os.path.isfile(full):
        raise SystemExit(f"release-audit-packet: missing file {path}")


def run_tool(args):
    proc = subprocess.run(args, cwd=repo_root, text=True, capture_output=True)
    text = proc.stdout.strip() if proc.returncode == 0 else (proc.stderr + "\n" + proc.stdout).strip()
    return proc.returncode, text


def add_check(name, status, message):
    checks.append({"name": name, "status": status, "message": message})


def add_tool_check(name, args):
    code, text = run_tool(args)
    add_check(name, "pass" if code == 0 else "fail", text)


def git_head():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root, text=True).strip()
    except Exception:
        return ""


def normalize_stats(text):
    return re.sub(r"(?m)^\*\*Generated \(UTC\):\*\* .+$", "**Generated (UTC):** <normalized>", text).strip()


require_path(release_evidence_json, "file")
require_path(signoff_manifest, "file")
require_path(archive_dir, "dir")
require_path(inventory, "file")

with open(os.path.join(repo_root, release_evidence_json) if not os.path.isabs(release_evidence_json) else release_evidence_json, "r", encoding="utf-8-sig") as handle:
    evidence = json.load(handle)
if not commit:
    commit = (evidence.get("commit") or {}).get("head") or git_head()

add_tool_check("release evidence schema", ["bash", os.path.join(script_dir, "release-json-schema-validate.sh"), "--schema", "docs/release-evidence-v1.schema.json", "--json", release_evidence_json])
add_tool_check("signoff manifest schema", ["bash", os.path.join(script_dir, "release-json-schema-validate.sh"), "--schema", "docs/release-signoff-manifest-v1.schema.json", "--json", signoff_manifest])
add_tool_check("signoff manifest gates", ["bash", os.path.join(script_dir, "release-signoff-manifest-validate.sh"), "--manifest", signoff_manifest])

archive_args = ["bash", os.path.join(script_dir, "release-archive-validate.sh"), "--archive-dir", archive_dir]
if allow_dry_run == "1":
    archive_args.append("--allow-dry-run")
add_tool_check("release archive", archive_args)
add_tool_check("artifact inventory", ["bash", os.path.join(script_dir, "artifact-inventory-validate.sh"), inventory])

ci_args = ["bash", os.path.join(script_dir, "release-ci-watch.sh"), "--commit", commit, "--json"]
if ci_mock_runs:
    ci_args.extend(["--mock-runs", ci_mock_runs])
add_tool_check("exact commit CI", ci_args)

stats_path = os.path.join(repo_root, "CODEBASE_STATS.md")
if not os.path.isfile(stats_path):
    add_check("codebase stats", "fail", "CODEBASE_STATS.md is missing")
elif strict_stats_freshness == "1":
    with open(stats_path, "r", encoding="utf-8") as handle:
        current_stats = handle.read()
    code, generated = run_tool(["node", "scripts/codebase-stats.mjs", "--dry-run"])
    if code != 0:
        add_check("codebase stats", "fail", generated)
    elif normalize_stats(current_stats) == normalize_stats(generated):
        add_check("codebase stats", "pass", "CODEBASE_STATS.md matches dry-run output after timestamp normalization")
    else:
        add_check("codebase stats", "fail", "CODEBASE_STATS.md is stale; run node scripts/codebase-stats.mjs in a clean release tree")
else:
    with open(stats_path, "r", encoding="utf-8") as handle:
        current_stats = handle.read()
    match = re.search(r"\*\*Generated \(UTC\):\*\* (.+)", current_stats)
    if match:
        add_check("codebase stats", "pass", f"CODEBASE_STATS.md generated at {match.group(1).strip()}")
    else:
        add_check("codebase stats", "fail", "CODEBASE_STATS.md has no generated timestamp")

failed = [check for check in checks if check["status"] != "pass"]
packet = {
    "schema_version": "release-audit-packet.v1",
    "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "commit": commit,
    "decision": "go" if not failed else "no-go",
    "release_evidence_json": release_evidence_json,
    "signoff_manifest": signoff_manifest,
    "archive_dir": archive_dir,
    "inventory": inventory,
    "checks": checks,
}

if json_output == "1":
    output = json.dumps(packet, indent=2)
else:
    lines = ["# Permawrite Release Audit Packet", "", f"Commit: {commit}", f"Decision: {packet['decision']}", ""]
    for check in checks:
        lines.append(f"- [{check['status']}] {check['name']}: {check['message']}")
    output = "\n".join(lines)

if output_path:
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(output + "\n")
    print(f"release-audit-packet: wrote {output_path}")
else:
    print(output)

if failed:
    sys.exit(1)
PY
