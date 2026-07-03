#!/usr/bin/env bash
# Fail if GitHub Actions workflow YAML is UTF-16 (GitHub cannot parse it).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW_DIR="${1:-$ROOT/.github/workflows}"
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY=python
fi
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "validate-workflow-encoding: python3 or python required" >&2
  exit 1
fi

"$PY" - "$WORKFLOW_DIR" <<'PY'
import sys
from pathlib import Path

workflow_dir = Path(sys.argv[1])
failed = []
paths = sorted(workflow_dir.glob("*.yml"))
for path in paths:
    data = path.read_bytes()[:64]
    if len(data) >= 2 and data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        failed.append(f"UTF-16 BOM {path}")
    elif data.count(b"\x00") >= 3:
        failed.append(f"null bytes {path}")
if failed:
    print("validate-workflow-encoding: FAIL", *failed, sep="\n", file=sys.stderr)
    sys.exit(1)
print(f"validate-workflow-encoding: OK ({len(paths)} workflow files UTF-8)")
PY
