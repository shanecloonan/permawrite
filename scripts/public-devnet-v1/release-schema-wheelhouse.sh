#!/usr/bin/env bash
# Download hash-pinned release-schema Python wheels for offline strict validation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ="$SCRIPT_DIR/requirements-release-schema.txt"
WHEELHOUSE="$SCRIPT_DIR/wheelhouse-release-schema"
PYTHON="${PERMAWRITE_RELEASE_SCHEMA_PYTHON:-python3}"

usage() {
  cat >&2 <<'USAGE'
usage: release-schema-wheelhouse.sh [--output DIR]

Downloads the pinned wheels in requirements-release-schema.txt into a local
wheelhouse for air-gapped release hosts. Re-run after bumping pinned versions.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      WHEELHOUSE="${2:?missing value for $1}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      echo "release-schema-wheelhouse: unknown argument $1" >&2
      exit 1
      ;;
  esac
done

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "release-schema-wheelhouse: python not found ($PYTHON)" >&2
  exit 1
fi

mkdir -p "$WHEELHOUSE"
"$PYTHON" -m pip download --disable-pip-version-check --require-hashes \
  -r "$REQ" -d "$WHEELHOUSE"
echo "release-schema-wheelhouse: PASS output=$WHEELHOUSE packages=$(find "$WHEELHOUSE" -maxdepth 1 -type f -name '*.whl' | wc -l | tr -d ' ')"
