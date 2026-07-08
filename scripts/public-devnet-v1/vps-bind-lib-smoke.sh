#!/usr/bin/env bash
# Regression: vps_export_binds must not abort under set -e when VPS binds are unset.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=vps-bind-lib.sh
source "$SCRIPT_DIR/vps-bind-lib.sh"
for role in hub v1 v2 observer; do
  vps_export_binds "$role"
done
echo "vps-bind-lib-smoke: PASS"
