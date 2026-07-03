#!/usr/bin/env bash
# Fail if GitHub Actions workflow YAML is UTF-16 (GitHub cannot parse it).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW_DIR="${1:-$ROOT/.github/workflows}"

failed=0
for path in "$WORKFLOW_DIR"/*.yml; do
  [[ -f "$path" ]] || continue
  if head -c 2 "$path" | od -An -tx1 | grep -qi 'ff fe'; then
    echo "validate-workflow-encoding: FAIL UTF-16 BOM $path" >&2
    failed=1
    continue
  fi
  if head -c 64 "$path" | grep -q $'\x00'; then
    echo "validate-workflow-encoding: FAIL null bytes (likely UTF-16) $path" >&2
    failed=1
  fi
done

if (( failed != 0 )); then
  exit 1
fi

count="$(find "$WORKFLOW_DIR" -maxdepth 1 -name '*.yml' | wc -l | tr -d ' ')"
echo "validate-workflow-encoding: OK ($count workflow files UTF-8)"
