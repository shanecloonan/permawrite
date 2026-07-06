#!/usr/bin/env bash
# Validate a filled release-candidate artifact inventory.
set -euo pipefail

if (($# != 1)); then
  echo "artifact-inventory-validate: pass inventory file path" >&2
  exit 1
fi

inventory="$1"
if [[ ! -f "$inventory" ]]; then
  echo "artifact-inventory-validate: missing file $inventory" >&2
  exit 1
fi

python3 - "$inventory" <<'PY'
import re
import sys

path = sys.argv[1]
issues = []
field_re = re.compile(r"^\s*(?:-\s*)?(Path or URL|SHA-256|SHA-256 or archive checksum|Reviewer|Decision):\s*(.*)$")

with open(path, "r", encoding="utf-8") as handle:
    lines = handle.readlines()

for index, raw in enumerate(lines, start=1):
    match = field_re.match(raw.rstrip("\n"))
    if not match:
        continue
    label, value = match.group(1), match.group(2).strip()
    if not value:
        issues.append(f"line {index}: '{label}' is required")
        continue
    if value.lower() in {"not applicable", "n/a"}:
        issues.append(f"line {index}: '{label}' uses '{value}' without a reason")

decision_values = []
for raw in lines:
    match = re.match(r"^\s*Decision:\s*(.+)$", raw.rstrip("\n"))
    if match:
        decision_values.append(match.group(1).strip())
if not decision_values:
    issues.append("missing final Decision field")
elif decision_values[0] not in {"go", "no-go"}:
    issues.append("final Decision must be 'go' or 'no-go'")

if issues:
    for issue in issues:
        print(f"artifact-inventory-validate: {issue}", file=sys.stderr)
    raise SystemExit(1)
print("artifact-inventory-validate: OK")
PY
