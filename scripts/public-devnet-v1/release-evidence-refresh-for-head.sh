#!/usr/bin/env bash
# Write release-evidence JSON/Markdown for the current HEAD under evidence/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

notes=""
operator=""
output_dir=""
allow_pending=0
run_rc_audit=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --notes) notes="${2:?missing value for --notes}"; shift 2 ;;
    --operator) operator="${2:?missing value for --operator}"; shift 2 ;;
    --output-dir) output_dir="${2:?missing value for --output-dir}"; shift 2 ;;
    --allow-pending-ci) allow_pending=1; shift ;;
    --run-rc-audit-dry-run) run_rc_audit=1; shift ;;
    *) echo "release-evidence-refresh-for-head.sh: unknown argument $1" >&2; exit 1 ;;
  esac
done

short_commit="$(git rev-parse --short HEAD)"
if [[ -z "$output_dir" ]]; then
  output_dir="$SCRIPT_DIR/evidence"
fi
mkdir -p "$output_dir"
json_path="$output_dir/release-evidence-${short_commit}.json"
md_path="$output_dir/release-evidence-${short_commit}.md"

common_args=()
if [[ -n "$operator" ]]; then
  common_args+=(-Operator "$operator")
fi
if [[ -n "$notes" ]]; then
  common_args+=(-Notes "$notes")
fi

pwsh -NoProfile -File "$SCRIPT_DIR/release-evidence.ps1" "${common_args[@]}" -Json -OutputPath "$json_path" >/dev/null
pwsh -NoProfile -File "$SCRIPT_DIR/release-evidence.ps1" "${common_args[@]}" -OutputPath "$md_path" >/dev/null

python3 - <<'PY' "$json_path" "$allow_pending"
import json, sys
path, allow_pending = sys.argv[1], sys.argv[2] == "1"
with open(path, encoding="utf-8") as fh:
    obj = json.load(fh)
ci = obj.get("ci") or {}
ok = ci.get("status") == "completed" and ci.get("conclusion") == "success"
if not ok and not allow_pending:
    raise SystemExit(
        f"release-evidence-refresh-for-head: GitHub CI is not green "
        f"(status={ci.get('status')} conclusion={ci.get('conclusion')}). "
        f"Re-run with --allow-pending-ci to record pending CI anyway."
    )
print(
    f"release-evidence-refresh-for-head: OK json={path} "
    f"ci_status={ci.get('status')} ci_conclusion={ci.get('conclusion')}"
)
PY

if [[ "$run_rc_audit" -eq 1 ]]; then
  rc_output="$(mktemp -t permawrite-rc-audit-refresh.XXXXXX.json)"
  pwsh -NoProfile -File "$SCRIPT_DIR/release-rc-audit-dry-run.ps1" \
    -ReleaseEvidenceJson "$json_path" \
    -OutputPath "$rc_output" \
    -Json >/dev/null
  python3 - <<'PY' "$rc_output"
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    obj = json.load(fh)
if obj.get("decision") != "go":
    raise SystemExit(f"release-evidence-refresh-for-head: RC audit dry-run decision={obj.get('decision')}")
print("release-evidence-refresh-for-head: RC audit dry-run decision=go")
PY
  rm -f "$rc_output"
fi

echo "release-evidence-refresh-for-head: OK md=$md_path"