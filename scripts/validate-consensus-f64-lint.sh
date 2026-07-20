#!/usr/bin/env bash
# B-36 / F10: consensus f64 arithmetic lint (see validate-consensus-f64-lint.py).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY=python
fi
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "validate-consensus-f64-lint: python3 or python required" >&2
  exit 1
fi
exec "$PY" "$ROOT/scripts/validate-consensus-f64-lint.py"