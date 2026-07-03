#!/usr/bin/env bash
# Build a final release-candidate audit packet from all machine-readable gates.
set -euo pipefail

release_evidence_json=""
signoff_manifest=""
archive_dir=""
inventory=""
commit=""
ci_mock_runs=""
participant_rehearsal_log=""
participant_support_bundle=""
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
  --participant-rehearsal-log FILE
                               Saved participant-rehearsal stdout/stderr transcript.
  --participant-support-bundle DIR
                               Support bundle directory named by the rehearsal PASS line.
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
    --participant-rehearsal-log) participant_rehearsal_log="${2:?missing value for --participant-rehearsal-log}"; shift 2 ;;
    --participant-support-bundle) participant_support_bundle="${2:?missing value for --participant-support-bundle}"; shift 2 ;;
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

python3 - "$REPO_ROOT" "$release_evidence_json" "$signoff_manifest" "$archive_dir" "$inventory" "$commit" "$ci_mock_runs" "$participant_rehearsal_log" "$participant_support_bundle" "$output_path" "$allow_dry_run" "$strict_stats_freshness" "$json_output" <<'PY'
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
    participant_rehearsal_log,
    participant_support_bundle,
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


def resolve_path(path):
    return path if os.path.isabs(path) else os.path.join(repo_root, path)


def same_bundle_reference(reported_bundle, provided_bundle):
    reported = reported_bundle.strip().strip('"')
    provided_abs = os.path.abspath(resolve_path(provided_bundle))
    reported_abs = os.path.abspath(resolve_path(reported))
    if os.path.exists(reported_abs):
        return reported_abs == provided_abs
    return os.path.basename(reported.rstrip("/\\")) == os.path.basename(provided_abs.rstrip("/\\"))


def add_participant_evidence_check(log_path, bundle_dir):
    if not log_path and not bundle_dir:
        return
    if not log_path or not bundle_dir:
        add_check("participant rehearsal evidence", "fail", "provide both participant rehearsal log and support bundle directory")
        return
    full_log = resolve_path(log_path)
    full_bundle = resolve_path(bundle_dir)
    if not os.path.isfile(full_log):
        add_check("participant rehearsal evidence", "fail", f"missing participant rehearsal log {log_path}")
        return
    if not os.path.isdir(full_bundle):
        add_check("participant rehearsal evidence", "fail", f"missing participant support bundle directory {bundle_dir}")
        return
    with open(full_log, "r", encoding="utf-8", errors="replace") as handle:
        log_text = handle.read()
    match = re.search(
        r"participant-rehearsal: PASS\s+commitment_hash=(?P<commit>[0-9a-fA-F]+)\s+restored_sha256=(?P<sha>[0-9a-fA-F]{64})\s+restored_path=(?P<restored>\S+)\s+support_bundle=(?P<bundle>\S+)",
        log_text,
    )
    if not match:
        add_check("participant rehearsal evidence", "fail", "participant rehearsal log missing final PASS line with commitment_hash, restored_sha256, restored_path, and support_bundle")
        return
    if not same_bundle_reference(match.group("bundle"), bundle_dir):
        add_check("participant rehearsal evidence", "fail", "participant rehearsal PASS support_bundle does not match provided support bundle directory")
        return
    manifest_path = os.path.join(full_bundle, "manifest.json")
    if not os.path.isfile(manifest_path):
        add_check("participant rehearsal evidence", "fail", "support bundle is missing manifest.json")
        return
    with open(manifest_path, "r", encoding="utf-8-sig") as handle:
        manifest = json.load(handle)
    commit_hash = match.group("commit").lower()
    if manifest.get("read_only") is not True:
        add_check("participant rehearsal evidence", "fail", "support bundle manifest is not marked read_only=true")
        return
    if str(manifest.get("commit_hash") or "").lower() != commit_hash:
        add_check("participant rehearsal evidence", "fail", "support bundle commit_hash does not match participant rehearsal PASS line")
        return
    command_names = {str(command.get("name")) for command in manifest.get("commands") or [] if isinstance(command, dict)}
    for required in ("node-status", "uploads-list", "operator-pool", "operator-challenge"):
        if required not in command_names:
            add_check("participant rehearsal evidence", "fail", f"support bundle missing required capture {required}")
            return
    add_check("participant rehearsal evidence", "pass", f"commitment_hash={commit_hash} restored_sha256={match.group('sha').lower()} support_bundle={bundle_dir}")


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
add_tool_check("participant smoke CI policy", ["bash", os.path.join(script_dir, "release-participant-smoke-policy-check.sh")])
add_participant_evidence_check(participant_rehearsal_log, participant_support_bundle)

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
    "participant_rehearsal_log": participant_rehearsal_log or None,
    "participant_support_bundle": participant_support_bundle or None,
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
