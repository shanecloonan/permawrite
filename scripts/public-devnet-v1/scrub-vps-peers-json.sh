#!/usr/bin/env bash
# B-68 / lane 7: scrub ephemeral TCP source ports out of mfnd peers.json before roll/restart.
# B-51 skips quarantine for non-durable peers, but polluted peers.json still marks those
# addresses durable -> vote fan-out dials dead ports -> tip stall after mfnd restart.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
DATA_ROOT="${MFN_DEVNET_DATA:-$REPO_ROOT/.permawrite-devnet-v1}"
PLAN_ONLY=0
APPLY=0
# Public socat + loopback committee listens on this VPS image.
ALLOW_PORTS="${MFN_PEERS_ALLOW_PORTS:-19001,19002,19003,19004,19101,19102,19103,19104}"
ALLOW_HOSTS="${MFN_PEERS_ALLOW_HOSTS:-127.0.0.1,5.161.201.73}"

usage() {
  cat <<'EOF'
usage: scrub-vps-peers-json.sh [--plan-only|--apply]

Rewrites v0/v1/v2(/observer) peers.json to committee listen addrs only.
Backs up each file to peers.json.pre-b68-<utc>.bak. Never restarts units.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "scrub-vps-peers-json: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "scrub-vps-peers-json: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "scrub-vps-peers-json: plan"
  echo "  unit=B-68"
  echo "  data_root=$DATA_ROOT"
  echo "  allow_hosts=$ALLOW_HOSTS"
  echo "  allow_ports=$ALLOW_PORTS"
  echo "  never=systemctl restart / faucet-http"
  echo "scrub-vps-peers-json: PASS plan-only"
  exit 0
fi

export DATA_ROOT ALLOW_PORTS ALLOW_HOSTS
python3 <<'PY'
import json, os, time
from pathlib import Path

root = Path(os.environ["DATA_ROOT"])
allow_ports = {int(x) for x in os.environ["ALLOW_PORTS"].split(",") if x.strip()}
allow_hosts = {x.strip() for x in os.environ["ALLOW_HOSTS"].split(",") if x.strip()}
utc = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

def scrub(path: Path) -> None:
    if not path.is_file():
        print(f"scrub-vps-peers-json: skip missing {path}")
        return
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        peers = raw
        wrap = None
    elif isinstance(raw, dict) and isinstance(raw.get("peers"), list):
        peers = raw["peers"]
        wrap = raw
    else:
        raise SystemExit(f"scrub-vps-peers-json: unknown shape {path}")
    kept = []
    dropped = 0
    for p in peers:
        s = str(p)
        try:
            host, port_s = s.rsplit(":", 1)
            port = int(port_s)
        except ValueError:
            dropped += 1
            continue
        if host in allow_hosts and port in allow_ports:
            kept.append(s)
        else:
            dropped += 1
    kept = sorted(set(kept))
    bak = path.with_name(f"{path.name}.pre-b68-{utc}.bak")
    bak.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    if wrap is None:
        out = kept
    else:
        wrap["peers"] = kept
        out = wrap
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"scrub-vps-peers-json: {path} kept={len(kept)} dropped={dropped} bak={bak.name}")

for name in ("v0", "v1", "v2", "observer"):
    scrub(root / name / "peers.json")
print("scrub-vps-peers-json: OK")
PY