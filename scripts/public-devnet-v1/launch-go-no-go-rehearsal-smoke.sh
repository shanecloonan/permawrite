#!/usr/bin/env bash
# Lane 7 / TL-9: plan-only launch-go-no-go schema rehearsal.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${MFN_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
OPS="$SCRIPT_DIR/OPERATORS.md"
PLAYBOOK="$REPO_ROOT/docs/TESTNET_LAUNCH.md"
PLAN_ONLY=1

usage() {
  cat <<EOF
usage: $(basename "$0") [--plan-only]

Validates launch-go-no-go.v1 JSON schema in pre-launch posture (automatable_pass=false).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan-only) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "$(basename "$0"): unknown argument $1" >&2; exit 1 ;;
  esac
done

for path in "$OPS" "$PLAYBOOK"; do
  if [[ ! -f "$path" ]]; then
    echo "launch-go-no-go-rehearsal-smoke: missing $path" >&2
    exit 1
  fi
done
if ! grep -qF "launch-go-no-go" "$OPS"; then
  echo "launch-go-no-go-rehearsal-smoke: OPERATORS.md missing launch-go-no-go" >&2
  exit 1
fi

set +e
combined="$(bash "$SCRIPT_DIR/launch-go-no-go.sh" --json 2>&1)"
exit_code=$?
set -e
if [[ "$exit_code" -eq 0 ]]; then
  echo "launch-go-no-go-rehearsal-smoke: expected non-zero exit before TL-5/TL-6 VPS evidence" >&2
  exit 1
fi

report="$(printf '%s' "$combined" | python3 -c "
import json, re, sys
text = sys.stdin.read()
match = re.search(r'\{[\s\S]*\"schema_version\"\s*:\s*\"launch-go-no-go\.v1\"[\s\S]*\}', text)
if not match:
    sys.exit(2)
print(match.group(0))
")" || {
  echo "launch-go-no-go-rehearsal-smoke: JSON block missing from launch-go-no-go.sh --json output" >&2
  exit 1
}

schema_version="$(printf '%s' "$report" | python3 -c "import json,sys; print(json.load(sys.stdin)['schema_version'])")"
genesis_id="$(printf '%s' "$report" | python3 -c "import json,sys; print(json.load(sys.stdin)['genesis_id'])")"
seed_count="$(printf '%s' "$report" | python3 -c "import json,sys; print(json.load(sys.stdin)['seed_nodes_count'])")"
automatable_pass="$(printf '%s' "$report" | python3 -c "import json,sys; print(json.load(sys.stdin)['automatable_pass'])")"
expected_genesis="454fa5d4a9bd6f59e35cf9ea7e68c096c9a271a92b2ec5931184e7f34a42a005"

if [[ "$schema_version" != "launch-go-no-go.v1" ]]; then
  echo "launch-go-no-go-rehearsal-smoke: expected launch-go-no-go.v1 got $schema_version" >&2
  exit 1
fi
if [[ "$genesis_id" != "$expected_genesis" ]]; then
  echo "launch-go-no-go-rehearsal-smoke: unexpected genesis_id $genesis_id" >&2
  exit 1
fi
if [[ "$automatable_pass" != "False" && "$automatable_pass" != "false" ]]; then
  echo "launch-go-no-go-rehearsal-smoke: pre-launch automatable_pass must be false got $automatable_pass" >&2
  exit 1
fi

echo "launch-go-no-go-rehearsal-smoke: plan"
echo "  schema=$schema_version"
echo "  genesis_id=$genesis_id"
echo "  seed_nodes_count=$seed_count"
echo "  automatable_pass=false"
echo "  checkpoint=Schnorr verify required when seed_nodes>=3 (mfn-cli checkpoint-log verify)"
echo "  helper=launch-go-no-go.sh [--json]"

if [[ "$PLAN_ONLY" -eq 1 ]]; then
  echo "launch-go-no-go-rehearsal-smoke: PASS plan-only"
  exit 0
fi

echo "launch-go-no-go-rehearsal-smoke: live mode not implemented" >&2
exit 1
