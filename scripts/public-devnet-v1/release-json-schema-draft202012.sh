#!/usr/bin/env bash
# Validate release JSON artifacts with pinned jsonschema Draft 2020-12.
set -euo pipefail

schema=""
json=""

usage() {
  cat <<'EOF'
usage: release-json-schema-draft202012.sh --schema FILE --json FILE

Requires the pinned Python dependency set in:
  scripts/public-devnet-v1/requirements-release-schema.txt
EOF
}

while (($# > 0)); do
  case "$1" in
    --schema) schema="${2:?missing value for --schema}"; shift 2 ;;
    --json) json="${2:?missing value for --json}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "release-json-schema-draft202012: unknown argument $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$schema" || -z "$json" ]]; then
  echo "release-json-schema-draft202012: --schema and --json are required" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "release-json-schema-draft202012: python3 is required" >&2
  exit 127
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${PERMAWRITE_RELEASE_SCHEMA_PYTHON:-python3}"
"$python_bin" "$SCRIPT_DIR/release-json-schema-draft202012.py" --schema "$schema" --json "$json"
