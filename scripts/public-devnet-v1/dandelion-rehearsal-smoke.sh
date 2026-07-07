#!/usr/bin/env bash
# B7: participant-rehearsal-smoke with Dandelion++ relay enabled on the mesh.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/participant-rehearsal-smoke.sh" --dandelion "$@"
