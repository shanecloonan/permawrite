#!/usr/bin/env bash
# B-23 / F18: privacy and permanence invariant gate (see validate-f18-impact-gate.py).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY=python
fi
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "validate-f18-impact-gate: python3 or python required" >&2
  exit 1
fi
"$PY" "$ROOT/scripts/validate-f18-impact-gate.py" --self-test
exec "$PY" "$ROOT/scripts/validate-f18-impact-gate.py"
