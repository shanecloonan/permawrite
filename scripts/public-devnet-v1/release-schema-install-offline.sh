#!/usr/bin/env bash
# Install hash-pinned release-schema Python deps from a local wheelhouse (no PyPI).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ="$SCRIPT_DIR/requirements-release-schema.txt"
WHEELHOUSE="$SCRIPT_DIR/wheelhouse-release-schema"
PYTHON="${PERMAWRITE_RELEASE_SCHEMA_PYTHON:-python3}"

usage() {
  cat >&2 <<'USAGE'
usage: release-schema-install-offline.sh [--wheelhouse DIR]

Installs scripts/public-devnet-v1/requirements-release-schema.txt from a local
wheelhouse built by release-schema-wheelhouse.sh.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wheelhouse)
      WHEELHOUSE="${2:?missing value for $1}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      echo "release-schema-install-offline: unknown argument $1" >&2
      exit 1
      ;;
  esac
done

if [[ ! -d "$WHEELHOUSE" ]]; then
  echo "release-schema-install-offline: missing wheelhouse at $WHEELHOUSE" >&2
  exit 1
fi

"$PYTHON" -m pip install --disable-pip-version-check --no-index \
  --find-links "$WHEELHOUSE" --require-hashes -r "$REQ"
"$PYTHON" -c "import importlib.metadata; assert importlib.metadata.version('jsonschema') == '4.17.3'"
echo "release-schema-install-offline: PASS wheelhouse=$WHEELHOUSE jsonschema=4.17.3"
