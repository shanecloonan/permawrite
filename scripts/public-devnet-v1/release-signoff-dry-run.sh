#!/usr/bin/env bash
# Exercise release evidence generation, support-bundle validation, and sign-off rendering without a live node.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR=""
CREATED_TEMP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
usage: release-signoff-dry-run.sh [--output-dir DIR]

Generates release-evidence JSON, validates it through support-bundle plan mode,
creates a minimal support-bundle fixture, and renders the sign-off checklist.
EOF
      exit 0
      ;;
    *)
      echo "release-signoff-dry-run: unknown argument $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$(mktemp -d)"
  CREATED_TEMP=1
fi
mkdir -p "$OUTPUT_DIR"
if (( CREATED_TEMP == 1 )); then
  trap 'rm -rf "$OUTPUT_DIR"' EXIT
fi

EVIDENCE_PATH="$OUTPUT_DIR/release-evidence.json"
bash "$SCRIPT_DIR/release-evidence.sh" \
  --json \
  --skip-ci-lookup \
  --operator dry-run \
  --notes "release sign-off dry-run fixture" \
  --output "$EVIDENCE_PATH" >/dev/null

support_plan="$(bash "$SCRIPT_DIR/support-bundle.sh" \
  --rpc 127.0.0.1:18731 \
  --release-evidence "$EVIDENCE_PATH" \
  --plan-only)"
if [[ "$support_plan" != *"valid release-evidence.v1"* ]]; then
  echo "release-signoff-dry-run: support-bundle did not validate generated release evidence" >&2
  exit 1
fi

BUNDLE_DIR="$OUTPUT_DIR/support-bundle"
mkdir -p "$BUNDLE_DIR"
cp "$EVIDENCE_PATH" "$BUNDLE_DIR/release-evidence.json"
for name in node-status.json uploads-list.json operator-pool.json wallet-status.json; do
  printf '{}\n' > "$BUNDLE_DIR/$name"
done
commit_head="$(python3 - "$EVIDENCE_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    print(json.load(handle)["commit"]["head"])
PY
)"
python3 - "$BUNDLE_DIR/manifest.json" "$commit_head" <<'PY'
import json
import sys

manifest_path, commit_head = sys.argv[1], sys.argv[2]
doc = {
    "release_evidence": {
        "provided": True,
        "valid": True,
        "copied_file": "release-evidence.json",
        "commit_head": commit_head,
    },
    "commands": [
        {"name": "node-status", "exit_code": 0, "stdout": "node-status.json", "stderr": None},
        {"name": "uploads-list", "exit_code": 0, "stdout": "uploads-list.json", "stderr": None},
        {"name": "operator-pool", "exit_code": 0, "stdout": "operator-pool.json", "stderr": None},
    ],
}
with open(manifest_path, "w", encoding="utf-8") as handle:
    json.dump(doc, handle, indent=2)
    handle.write("\n")
PY

review="$(bash "$SCRIPT_DIR/release-signoff-review.sh" --bundle-dir "$BUNDLE_DIR")"
for required in "# Permawrite Release Sign-Off Bundle Review" "release-evidence.v1" "Required Approvals" "Command failures: \`none\`"; do
  if [[ "$review" != *"$required"* ]]; then
    echo "release-signoff-dry-run: rendered review missing '$required'" >&2
    exit 1
  fi
done
printf '%s\n' "$review" > "$OUTPUT_DIR/release-signoff-review.md"

echo "release-signoff-dry-run: output_dir=$OUTPUT_DIR"
echo "release-signoff-dry-run: OK"
