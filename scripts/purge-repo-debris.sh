#!/usr/bin/env bash
# M2.5.39: remove gitignored local debris only (never tracked paths).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--what-if" ]]; then
  echo "purge-repo-debris: git clean -n -d -X"
  git clean -n -d -X
else
  echo "purge-repo-debris: git clean -f -d -X"
  git clean -f -d -X
fi
