#!/usr/bin/env bash
# Validate participant rehearsal smoke policy in CI automation files.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${PERMAWRITE_RELEASE_SCHEMA_PYTHON:-python3}"
exec "$python_bin" "$SCRIPT_DIR/release-participant-smoke-policy-check.py" "$@"
