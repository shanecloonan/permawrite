#!/usr/bin/env bash
# Lane 7 / TL-6: participant rehearsal on internet-facing VPS (fund -> upload -> prove).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
for bin in mfnd mfn-cli mfn-storage-operator; do
  if [[ ! -x "$REPO_ROOT/target/release/$bin" ]]; then
    echo "vps-participant-rehearsal: build release binaries first (mfnd, mfn-cli, mfn-storage-operator)" >&2
    exit 1
  fi
done
exec bash "$SCRIPT_DIR/participant-rehearsal-smoke.sh" \
  --vps \
  --with-observer \
  --archive-evidence \
  --min-hub-height "${MFN_VPS_REHEARSAL_MIN_HEIGHT:-10}" \
  --no-build \
  "$@"
