#!/usr/bin/env bash
# Lane 7 / TL-5: internet-facing VPS soak gate (height >= 10, multi-sample health).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
MFND="$REPO_ROOT/target/release/mfnd"
if [[ ! -x "$MFND" ]]; then
  echo "vps-internet-soak: build mfnd first: cargo build -p mfn-node --release --bin mfnd" >&2
  exit 1
fi
"$SCRIPT_DIR/vps-preflight.sh"
exec bash "$SCRIPT_DIR/soak.sh" \
  --vps \
  --duration-minutes "${MFN_VPS_SOAK_MINUTES:-20}" \
  --min-final-height "${MFN_VPS_SOAK_MIN_HEIGHT:-10}" \
  --min-successful-iterations "${MFN_VPS_SOAK_MIN_ITERATIONS:-3}" \
  --stall-samples "${MFN_VPS_SOAK_STALL_SAMPLES:-2}" \
  --archive-evidence \
  "$@"
