#!/usr/bin/env bash
# B-70: fail-closed if peers.json contains non-persistable addrs (ephemeral / 0.0.0.0).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
DATA_ROOT="${MFN_DEVNET_DATA:-$REPO_ROOT/.permawrite-devnet-v1}"
PLAN_ONLY=0

usage() {
  cat <<'EOF'
usage: assert-vps-peers-clean.sh [--plan-only]

Fails if any v0/v1/v2/observer peers.json entry is unspecified (0.0.0.0/::)
or uses an IANA dynamic port (>=32768). Does not restart units.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "assert-vps-peers-clean: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY )); then
  echo "assert-vps-peers-clean: plan"
  echo "  unit=B-70"
  echo "  data_root=$DATA_ROOT"
  echo "assert-vps-peers-clean: PASS plan-only"
  exit 0
fi

export DATA_ROOT
python3 <<'PY'
import json, os, sys
from pathlib import Path

root = Path(os.environ["DATA_ROOT"])
bad = []
for name in ("v0", "v1", "v2", "observer"):
    path = root / name / "peers.json"
    if not path.is_file():
        continue
    raw = json.loads(path.read_text(encoding="utf-8"))
    peers = raw["peers"] if isinstance(raw, dict) else raw
    for p in peers:
        s = str(p)
        try:
            host, port_s = s.rsplit(":", 1)
            port = int(port_s)
        except ValueError:
            bad.append((name, s, "malformed"))
            continue
        if host in ("0.0.0.0", "::", "[::]"):
            bad.append((name, s, "unspecified"))
        elif port >= 32768 or port == 0:
            bad.append((name, s, "dynamic_port"))
if bad:
    for name, s, why in bad:
        print(f"assert-vps-peers-clean: FAIL {name} {s} ({why})", file=sys.stderr)
    sys.exit(1)
print("assert-vps-peers-clean: OK")
PY