#!/usr/bin/env bash
# Run shellcheck on scripts/shellcheck-files.txt.
# CI installs shellcheck. Local ci-check runs this when the binary is present.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIST="$ROOT/scripts/shellcheck-files.txt"

if ! command -v shellcheck >/dev/null 2>&1; then
  echo "shellcheck-ci: shellcheck is not installed" >&2
  exit 127
fi

count=0
while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    ""|\#*) continue ;;
  esac
  echo "shellcheck-ci: $line"
  shellcheck --source-path=SCRIPTDIR -x "$ROOT/$line"
  count=$((count + 1))
done <"$LIST"

if (( count == 0 )); then
  echo "shellcheck-ci: no files listed" >&2
  exit 1
fi
echo "shellcheck-ci: PASS ($count files)"
