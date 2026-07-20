#!/usr/bin/env bash
# B-79 / lane 7: read-only B-32 arm-ready inventory (no faucet, no mfnd restart).
# Reports whether the live public tip + host inventory can support a B-32 multi-op pack.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PLAN_ONLY=0
APPLY=0
RPC="${MFN_ROLL_RPC:-127.0.0.1:18731}"
PUBLIC_HOST="${MFN_B32_PUBLIC_HOST:-5.161.201.73}"

usage() {
  cat <<'EOF'
usage: assert-b32-arm-ready.sh [--plan-only|--apply]

Read-only checks for B-32 multi-op arming:
  tip readable + advancing, peers-clean, B-71 binary/source marker,
  CI roll gate (B-78), recent uploads with last_proven, distinct public hosts.
Never restarts faucet/mfnd. Exit 0 only when arm-ready (>=2 distinct hosts).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "assert-b32-arm-ready: unknown $1" >&2; exit 1 ;;
  esac
done

if (( PLAN_ONLY == 0 && APPLY == 0 )); then
  echo "assert-b32-arm-ready: specify --plan-only or --apply" >&2
  exit 1
fi

if (( PLAN_ONLY )); then
  echo "assert-b32-arm-ready: plan"
  echo "  unit=B-79"
  echo "  checks=tip peers B-71 CI-gate uploads distinct_hosts>=2"
  echo "  never=faucet-http mfnd restart join-testnet-rehearsal"
  echo "assert-b32-arm-ready: PASS plan-only"
  exit 0
fi

cd "$REPO_ROOT"
fail=0

rpc_call() {
  local method="$1"
  # Quote default "{}": bare ${2:-{}} parses as default "{" + stray "}".
  local params_json="${2:-"{}"}"
  python3 - "$RPC" "$method" "$params_json" <<'PY'
import json, socket, sys
rpc, method, params_raw = sys.argv[1], sys.argv[2], sys.argv[3]
params = json.loads(params_raw)
host, port = rpc.rsplit(":", 1)
s = socket.create_connection((host, int(port)), 12)
s.sendall((json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}) + "\n").encode())
buf = b""
while b"\n" not in buf and len(buf) < 2_000_000:
    c = s.recv(65536)
    if not c:
        break
    buf += c
# One JSON-RPC object (tolerate trailing noise after the first value).
raw = buf.decode()
obj, _ = json.JSONDecoder().raw_decode(raw.lstrip())
print(json.dumps(obj, separators=(",", ":")))
PY
}

tip_h="$(rpc_call get_tip | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["tip_height"])')"
echo "assert-b32-arm-ready: tip_height=$tip_h"
sleep 8
tip_h2="$(rpc_call get_tip | python3 -c 'import sys,json; print(json.load(sys.stdin)["result"]["tip_height"])')"
if (( tip_h2 < tip_h )); then
  echo "assert-b32-arm-ready: FAIL tip went backwards $tip_h -> $tip_h2" >&2
  fail=1
elif (( tip_h2 == tip_h )); then
  echo "assert-b32-arm-ready: WARN tip flat over 8s (may be slow seal); tip=$tip_h2"
else
  echo "assert-b32-arm-ready: tip advancing $tip_h -> $tip_h2"
fi

if [[ -f "$SCRIPT_DIR/assert-vps-peers-clean.sh" ]]; then
  if bash "$SCRIPT_DIR/assert-vps-peers-clean.sh" >/tmp/b32-peers.out 2>&1; then
    echo "assert-b32-arm-ready: peers-clean OK"
  else
    echo "assert-b32-arm-ready: FAIL peers-clean" >&2
    cat /tmp/b32-peers.out >&2 || true
    fail=1
  fi
fi

if grep -q "is_persistable_peer_addr" "$REPO_ROOT/mfn-node/src/p2p_fanout.rs" 2>/dev/null \
  || { [[ -x "$REPO_ROOT/target/release/mfnd" ]] && strings "$REPO_ROOT/target/release/mfnd" | grep -q is_persistable_peer_addr; }; then
  echo "assert-b32-arm-ready: B-71 persistable-peer marker OK"
else
  echo "assert-b32-arm-ready: FAIL missing B-71 persistable-peer marker" >&2
  fail=1
fi

# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib-ci-roll-gate.sh"
export MFN_REPO_ROOT="$REPO_ROOT"
if gate_line="$(mfn_ci_roll_gate_check)"; then
  echo "assert-b32-arm-ready: $gate_line"
else
  echo "assert-b32-arm-ready: FAIL CI roll gate" >&2
  fail=1
fi

uploads_json="$(rpc_call list_recent_uploads '{"limit":8}')"
proven="$(printf '%s' "$uploads_json" | python3 -c '
import sys,json
raw=sys.stdin.read()
d=json.JSONDecoder().raw_decode(raw.lstrip())[0]
ups=(d.get("result") or {}).get("uploads") or []
proven=[u for u in ups if int(u.get("last_proven_height") or 0)>0]
print(len(proven))
print((d.get("result") or {}).get("total") or 0)
')"
proven_n="$(printf '%s\n' "$proven" | sed -n '1p')"
total_n="$(printf '%s\n' "$proven" | sed -n '2p')"
echo "assert-b32-arm-ready: uploads_total=$total_n recent_proven=$proven_n"
if (( proven_n < 1 )); then
  echo "assert-b32-arm-ready: FAIL no recent last_proven uploads (need live SPoRA history)" >&2
  fail=1
fi

# Distinct public hosts: env override comma-list, else single known public seed host.
hosts_csv="${MFN_B32_OPERATOR_HOSTS:-$PUBLIC_HOST}"
IFS=',' read -r -a hosts <<<"$hosts_csv"
# trim empties
clean=()
for h in "${hosts[@]}"; do
  h="$(echo "$h" | tr -d '[:space:]')"
  [[ -n "$h" ]] && clean+=("$h")
done
# unique
mapfile -t uniq < <(printf '%s\n' "${clean[@]}" | awk 'NF && !seen[$0]++')
host_count="${#uniq[@]}"
echo "assert-b32-arm-ready: distinct_hosts=$host_count hosts=${uniq[*]}"
if (( host_count < 2 )); then
  echo "assert-b32-arm-ready: NOT READY — need >=2 distinct operator hosts for B-32 (set MFN_B32_OPERATOR_HOSTS=host1,host2)" >&2
  fail=1
fi

if (( fail )); then
  echo "assert-b32-arm-ready: NOT READY tip=$tip_h2" >&2
  exit 1
fi
echo "assert-b32-arm-ready: READY tip=$tip_h2 distinct_hosts=$host_count"