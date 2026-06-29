#!/usr/bin/env bash
# Generate a public-devnet release-candidate evidence checklist.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STATS_PATH="$REPO_ROOT/CODEBASE_STATS.md"
EXPECTED_GENESIS_ID="7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df"

RPC=""
RPC_API_KEY=""
OUTPUT_PATH=""
OPERATOR=""
NOTES=""
RUN_HEALTH=0
JSON_OUTPUT=0
SKIP_CI_LOOKUP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc) RPC="${2:?}"; shift 2 ;;
    --rpc-api-key) RPC_API_KEY="${2:?}"; shift 2 ;;
    --output) OUTPUT_PATH="${2:?}"; shift 2 ;;
    --operator) OPERATOR="${2:?}"; shift 2 ;;
    --notes) NOTES="${2:?}"; shift 2 ;;
    --run-health-check) RUN_HEALTH=1; shift ;;
    --json) JSON_OUTPUT=1; shift ;;
    --skip-ci-lookup) SKIP_CI_LOOKUP=1; shift ;;
    -h|--help)
      cat <<'USAGE'
Usage: release-evidence.sh [--rpc HOST:PORT] [--rpc-api-key KEY] [--run-health-check] [--json]
                           [--skip-ci-lookup]
                           [--operator NAME] [--notes TEXT] [--output FILE]

Generates a Markdown release-candidate evidence record by default. Use --json
for machine-readable output. Unknown evidence is printed as unknown rather than
treated as a pass.
USAGE
      exit 0
      ;;
    *) echo "release-evidence: unknown argument $1" >&2; exit 2 ;;
  esac
done

git_text() {
  (cd "$REPO_ROOT" && git "$@" 2>/dev/null || true) | tr -d '\r'
}

remote_slug() {
  local remote
  remote="$(git_text remote get-url origin | head -n 1)"
  if [[ "$remote" =~ github.com[:/]([^/]+)/([^/.]+)(\.git)?$ ]]; then
    printf '%s/%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
  fi
}

stats_timestamp() {
  if [[ ! -f "$STATS_PATH" ]]; then
    echo "missing"
    return
  fi
  sed -n 's/^\*\*Generated (UTC):\*\* //p' "$STATS_PATH" | head -n 1
}

ci_status() {
  local commit="$1" slug run
  slug="$(remote_slug || true)"
  if [[ -z "$slug" ]]; then
    echo "unknown||no github remote|"
    return
  fi
  if command -v gh >/dev/null 2>&1; then
    run="$(gh run list --workflow CI --branch main --limit 10 --json headSha,status,conclusion,url 2>/dev/null | tr -d '\n' || true)"
    if [[ "$run" == *"$commit"* ]]; then
      local chunk status conclusion url
      chunk="$(printf '%s' "$run" | sed "s/},{/}\n{/g" | grep "$commit" | head -n 1)"
      status="$(printf '%s' "$chunk" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p')"
      conclusion="$(printf '%s' "$chunk" | sed -n 's/.*"conclusion":\([^,}]*\).*/\1/p' | tr -d '"')"
      url="$(printf '%s' "$chunk" | sed -n 's/.*"url":"\([^"]*\)".*/\1/p')"
      echo "${status:-unknown}|${conclusion}|gh|${url}"
      return
    fi
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$slug" "$commit" <<'PY'
import json
import sys
import urllib.request

slug, commit = sys.argv[1], sys.argv[2]
url = f"https://api.github.com/repos/{slug}/actions/workflows/ci.yml/runs?branch=main&per_page=10"
try:
    req = urllib.request.Request(url, headers={"User-Agent": "permawrite-release-evidence"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.load(resp)
    for run in data.get("workflow_runs", []):
        if run.get("head_sha") == commit:
            print(f"{run.get('status','unknown')}|{run.get('conclusion') or ''}|github-api|{run.get('html_url','')}")
            break
    else:
        print("unknown||not found|")
except Exception as exc:
    print(f"unknown||github-api error: {exc}|")
PY
    return
  fi
  echo "unknown||python3 unavailable|"
}

rpc_status_line() {
  local addr="$1"
  if [[ -z "$addr" ]]; then
    echo "not provided|||||||||"
    return
  fi
  if ! command -v nc >/dev/null 2>&1; then
    echo "$addr|unknown|unknown|unknown|unknown|unknown|unknown|unknown|unknown|nc unavailable"
    return
  fi
  local host port line
  host="${addr%:*}"
  port="${addr##*:}"
  line="$(printf '%s\n' '{"jsonrpc":"2.0","method":"get_status","id":1}' | nc -w 3 "$host" "$port" 2>/dev/null || true)"
  if [[ -z "$line" ]]; then
    echo "$addr|unknown|unknown|unknown|unknown|unknown|unknown|unknown|unknown|empty response"
    return
  fi
  local genesis height tip listen public_bind auth current max sessions peers
  genesis="$(printf '%s' "$line" | sed -n 's/.*"genesis_id":"\([^"]*\)".*/\1/p')"
  height="$(printf '%s' "$line" | sed -n 's/.*"tip_height":\([0-9]*\).*/\1/p')"
  tip="$(printf '%s' "$line" | sed -n 's/.*"tip_id":"\([^"]*\)".*/\1/p')"
  listen="$(printf '%s' "$line" | sed -n 's/.*"listen_addr":"\([^"]*\)".*/\1/p')"
  public_bind="$(printf '%s' "$line" | sed -n 's/.*"public_bind":\([^,}]*\).*/\1/p')"
  auth="$(printf '%s' "$line" | sed -n 's/.*"auth_enabled":\([^,}]*\).*/\1/p')"
  current="$(printf '%s' "$line" | sed -n 's/.*"current_in_flight":\([0-9]*\).*/\1/p')"
  max="$(printf '%s' "$line" | sed -n 's/.*"max_in_flight":\([0-9]*\).*/\1/p')"
  sessions="$(printf '%s' "$line" | sed -n 's/.*"session_count":\([0-9]*\).*/\1/p')"
  peers="$(printf '%s' "$line" | sed -n 's/.*"peer_count":\([0-9]*\).*/\1/p')"
  echo "$addr|${genesis:-unknown}|${height:-unknown}|${tip:-unknown}|${listen:-unknown}|${public_bind:-unknown}|${auth:-unknown}|${current:-unknown}/${max:-unknown}|${sessions:-unknown}/${peers:-unknown}|"
}

health_status() {
  if (( RUN_HEALTH == 0 )); then
    echo "not run|"
    return
  fi
  local out
  if out="$(bash "$SCRIPT_DIR/health-check.sh" 2>&1)"; then
    echo "pass|$out"
  else
    echo "fail|$out"
  fi
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

HEAD_SHA="$(git_text rev-parse HEAD | head -n 1)"
BRANCH="$(git_text branch --show-current | head -n 1)"
DIRTY="$(git_text status --short)"
DIRTY_STATE="clean"
if [[ -n "$DIRTY" ]]; then DIRTY_STATE="dirty"; fi
STATS_GENERATED="$(stats_timestamp)"
if (( SKIP_CI_LOOKUP == 1 )); then
  CI_INFO="unknown||skipped|"
else
  CI_INFO="$(ci_status "$HEAD_SHA")"
fi
IFS='|' read -r CI_STATE CI_CONCLUSION CI_SOURCE CI_URL <<< "$CI_INFO"
RPC_INFO="$(rpc_status_line "$RPC")"
IFS='|' read -r RPC_ADDR RPC_GENESIS RPC_HEIGHT RPC_TIP RPC_LISTEN RPC_PUBLIC RPC_AUTH RPC_INFLIGHT RPC_P2P RPC_NOTE <<< "$RPC_INFO"
RPC_CURRENT_IN_FLIGHT="${RPC_INFLIGHT%/*}"
RPC_MAX_IN_FLIGHT="${RPC_INFLIGHT##*/}"
RPC_P2P_SESSION_COUNT="${RPC_P2P%/*}"
RPC_P2P_PEER_COUNT="${RPC_P2P##*/}"
HEALTH_INFO="$(health_status)"
IFS='|' read -r HEALTH_STATE HEALTH_OUTPUT <<< "$HEALTH_INFO"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

if (( JSON_OUTPUT == 1 )); then
  {
    echo "{"
    echo "  \"schema_version\": \"release-evidence.v1\","
    echo "  \"generated_utc\": \"$(json_escape "$GENERATED_AT")\","
    echo "  \"commit\": {"
    echo "    \"branch\": \"$(json_escape "${BRANCH:-unknown}")\","
    echo "    \"head\": \"$(json_escape "${HEAD_SHA:-unknown}")\","
    echo "    \"working_tree\": \"$(json_escape "$DIRTY_STATE")\","
    echo "    \"codebase_stats_generated_utc\": \"$(json_escape "${STATS_GENERATED:-missing}")\""
    echo "  },"
    echo "  \"ci\": {"
    echo "    \"status\": \"$(json_escape "${CI_STATE:-unknown}")\","
    echo "    \"conclusion\": \"$(json_escape "${CI_CONCLUSION:-}")\","
    echo "    \"source\": \"$(json_escape "${CI_SOURCE:-unknown}")\","
    echo "    \"url\": \"$(json_escape "${CI_URL:-}")\""
    echo "  },"
    echo "  \"chain\": {"
    echo "    \"expected_genesis_id\": \"$(json_escape "$EXPECTED_GENESIS_ID")\""
    echo "  },"
    echo "  \"health\": {"
    echo "    \"status\": \"$(json_escape "$HEALTH_STATE")\","
    echo "    \"output\": \"$(json_escape "${HEALTH_OUTPUT:-}")\""
    echo "  },"
    echo "  \"rpc\": {"
    echo "    \"endpoint\": \"$(json_escape "$RPC_ADDR")\","
    echo "    \"genesis_id\": \"$(json_escape "${RPC_GENESIS:-unknown}")\","
    echo "    \"tip_height\": \"$(json_escape "${RPC_HEIGHT:-unknown}")\","
    echo "    \"tip_id\": \"$(json_escape "${RPC_TIP:-unknown}")\","
    echo "    \"listen_addr\": \"$(json_escape "${RPC_LISTEN:-unknown}")\","
    echo "    \"public_bind\": \"$(json_escape "${RPC_PUBLIC:-unknown}")\","
    echo "    \"auth_enabled\": \"$(json_escape "${RPC_AUTH:-unknown}")\","
    echo "    \"current_in_flight\": \"$(json_escape "${RPC_CURRENT_IN_FLIGHT:-unknown}")\","
    echo "    \"max_in_flight\": \"$(json_escape "${RPC_MAX_IN_FLIGHT:-unknown}")\","
    echo "    \"p2p_session_count\": \"$(json_escape "${RPC_P2P_SESSION_COUNT:-unknown}")\","
    echo "    \"p2p_peer_count\": \"$(json_escape "${RPC_P2P_PEER_COUNT:-unknown}")\","
    echo "    \"note\": \"$(json_escape "${RPC_NOTE:-}")\""
    echo "  },"
    echo "  \"operator_signoff\": {"
    echo "    \"operator\": \"$(json_escape "$OPERATOR")\","
    echo "    \"threat_model_reviewed\": false,"
    echo "    \"residual_risks_have_named_owners\": false,"
    echo "    \"rpc_exposure_approved\": false,"
    echo "    \"backups_and_restore_rehearsed\": false,"
    echo "    \"halt_rollback_authority_agreed\": false,"
    echo "    \"notes\": \"$(json_escape "$NOTES")\""
    echo "  }"
    echo "}"
  } > "${OUTPUT_PATH:-/dev/stdout}"
  if [[ -n "$OUTPUT_PATH" ]]; then
    echo "release-evidence: wrote $OUTPUT_PATH"
  fi
  exit 0
fi

{
  echo "# Permawrite Release-Candidate Evidence"
  echo
  echo "Generated UTC: \`$GENERATED_AT\`"
  echo
  echo "## Commit And CI"
  echo
  echo "- Branch: \`${BRANCH:-unknown}\`"
  echo "- Commit: \`${HEAD_SHA:-unknown}\`"
  echo "- Working tree: \`$DIRTY_STATE\`"
  echo "- CODEBASE_STATS generated UTC: \`${STATS_GENERATED:-missing}\`"
  echo "- GitHub CI: status=\`${CI_STATE:-unknown}\` conclusion=\`${CI_CONCLUSION:-}\` source=\`${CI_SOURCE:-unknown}\`"
  if [[ -n "${CI_URL:-}" ]]; then echo "- GitHub CI URL: $CI_URL"; fi
  echo
  echo "## Chain And Health"
  echo
  echo "- Expected public-devnet genesis_id: \`$EXPECTED_GENESIS_ID\`"
  echo "- Health check: \`$HEALTH_STATE\`"
  if [[ -n "${HEALTH_OUTPUT:-}" ]]; then
    echo
    echo '```text'
    echo "$HEALTH_OUTPUT"
    echo '```'
  fi
  echo
  echo "## RPC Posture"
  echo
  echo "- RPC endpoint checked: \`$RPC_ADDR\`"
  echo "- genesis_id: \`${RPC_GENESIS:-unknown}\`"
  echo "- tip_height: \`${RPC_HEIGHT:-unknown}\`"
  echo "- tip_id: \`${RPC_TIP:-unknown}\`"
  echo "- rpc.listen_addr: \`${RPC_LISTEN:-unknown}\`"
  echo "- rpc.public_bind: \`${RPC_PUBLIC:-unknown}\`"
  echo "- rpc.auth_enabled: \`${RPC_AUTH:-unknown}\`"
  echo "- rpc.current_in_flight / max_in_flight: \`${RPC_INFLIGHT:-unknown}\`"
  echo "- p2p.session_count / peer_count: \`${RPC_P2P:-unknown}\`"
  if [[ -n "${RPC_NOTE:-}" ]]; then echo "- RPC note: \`$RPC_NOTE\`"; fi
  echo
  echo "## Operator Sign-Off"
  echo
  echo "- Operator: \`$OPERATOR\`"
  echo "- Threat model reviewed: \`[ ]\`"
  echo "- Residual risks have named owners: \`[ ]\`"
  echo "- RPC exposure approved: \`[ ]\`"
  echo "- Backups and restore rehearsed: \`[ ]\`"
  echo "- Halt/rollback authority agreed: \`[ ]\`"
  echo "- Notes: \`$NOTES\`"
} > "${OUTPUT_PATH:-/dev/stdout}"

if [[ -n "$OUTPUT_PATH" ]]; then
  echo "release-evidence: wrote $OUTPUT_PATH"
fi
