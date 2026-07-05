#!/usr/bin/env bash
# Mirror validate-rc-helper-scripts.ps1 for Linux/macOS ci-check.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoProfile -File scripts/validate-rc-helper-scripts.ps1
elif command -v powershell >/dev/null 2>&1; then
  powershell -NoProfile -File scripts/validate-rc-helper-scripts.ps1
else
  echo "validate-rc-helper-scripts: missing pwsh/powershell" >&2
  exit 127
fi
