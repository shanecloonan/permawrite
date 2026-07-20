#!/usr/bin/env bash
# B-78: shared CI gate for VPS mfnd rolls.
# Accepts (1) latest CI success on HEAD, or (2) ancestor GREEN when HEAD..ancestor
# touches only non-protocol paths (JOIN docs thrash must not block rolls).
#
# Usage (from assert-vps-roll-ready / vps-roll-mfnd):
#   # shellcheck source=/dev/null
#   source "$SCRIPT_DIR/lib-ci-roll-gate.sh"
#   mfn_ci_roll_gate_check || exit $?
#
# Env:
#   MFN_ROLL_CI_API   — override Actions API URL (default: CI workflow runs on main)
#   MFN_ROLL_ALLOW_RED_CI=1 — skip (caller handles)

mfn_ci_roll_gate_is_protocol_path() {
  # Paths that can change the mfnd binary / CI contract. Testdata (incl. checkpoint
  # logs), docs, scripts, and board updates are docs-equivalent for roll purposes.
  local p="$1"
  case "$p" in
    Cargo.toml|Cargo.lock|.github/workflows/*|rust-toolchain|rust-toolchain.toml|deny.toml)
      return 0
      ;;
    mfn-*/src/*|mfn-*/build.rs|mfn-*/Cargo.toml|mfn-*/Cargo.lock)
      return 0
      ;;
  esac
  return 1
}

# Prints: mfn_ci_roll_gate: OK #<run_id> <short_sha> <mode>
# mode = head | docs-equivalent
# Returns 0 on pass, 1 on fail (message on stderr).
mfn_ci_roll_gate_check() {
  local repo_root="${MFN_REPO_ROOT:-}"
  if [[ -z "$repo_root" ]]; then
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  fi
  cd "$repo_root"

  local api_url="${MFN_ROLL_CI_API:-https://api.github.com/repos/shanecloonan/permawrite/actions/workflows/ci.yml/runs?branch=main&per_page=15}"
  local api_body
  api_body="$(curl -fsS --max-time 25 -H 'Accept: application/vnd.github+json' -H 'User-Agent: permawrite-ci-roll-gate' "$api_url" || true)"
  if [[ -z "$api_body" ]]; then
    echo "mfn_ci_roll_gate: FAIL cannot read CI API" >&2
    return 1
  fi

  local eval_out
  eval_out="$(printf '%s' "$api_body" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    runs = d.get("workflow_runs") or []
except Exception:
    runs = []
if not runs:
    print("EMPTY")
    sys.exit(0)
latest = runs[0]
# pipe-delimited so empty conclusion cannot shift fields under set -u
def cell(x):
    s = "" if x is None else str(x)
    return s.replace("|", "/")
print("LATEST|" + "|".join([
    cell(latest.get("id")),
    cell(latest.get("status")),
    cell(latest.get("conclusion")),
    cell(latest.get("head_sha")),
]))
for r in runs:
    if (r.get("status") == "completed") and (r.get("conclusion") == "success"):
        print("GREEN|" + cell(r.get("id")) + "|" + cell(r.get("head_sha")))
' 2>/dev/null || echo EMPTY)"

  if [[ "$eval_out" == "EMPTY" ]] || [[ -z "$eval_out" ]]; then
    echo "mfn_ci_roll_gate: FAIL no CI runs" >&2
    return 1
  fi

  local latest_line
  latest_line="$(printf '%s\n' "$eval_out" | head -n1)"
  IFS='|' read -r tag run_id status conclusion head_sha <<<"$latest_line"
  if [[ "$tag" != "LATEST" ]]; then
    echo "mfn_ci_roll_gate: FAIL parse latest" >&2
    return 1
  fi

  if [[ -z "$run_id" ]]; then
    echo "mfn_ci_roll_gate: FAIL empty run id" >&2
    return 1
  fi

  if [[ "$status" == "completed" && "$conclusion" == "success" ]]; then
    echo "mfn_ci_roll_gate: OK #$run_id ${head_sha:0:7} head"
    return 0
  fi

  local green_lines
  green_lines="$(printf '%s\n' "$eval_out" | grep '^GREEN|' || true)"
  if [[ -z "$green_lines" ]]; then
    echo "mfn_ci_roll_gate: FAIL CI #$run_id status=$status conclusion=$conclusion (no recent GREEN)" >&2
    return 1
  fi

  local g_tag g_id g_sha
  while IFS='|' read -r g_tag g_id g_sha; do
    [[ "$g_tag" == "GREEN" ]] || continue
    [[ -n "$g_sha" ]] || continue
    if ! git cat-file -e "${g_sha}^{commit}" 2>/dev/null; then
      git fetch origin main --quiet 2>/dev/null || true
    fi
    if ! git merge-base --is-ancestor "$g_sha" HEAD 2>/dev/null; then
      continue
    fi
    local bad=""
    local path
    while IFS= read -r path; do
      [[ -z "$path" ]] && continue
      if mfn_ci_roll_gate_is_protocol_path "$path"; then
        bad="$path"
        break
      fi
    done < <(git diff --name-only "$g_sha"..HEAD 2>/dev/null || true)
    if [[ -n "$bad" ]]; then
      echo "mfn_ci_roll_gate: FAIL CI #$run_id $status; ancestor GREEN #$g_id but protocol path changed: $bad" >&2
      return 1
    fi
    echo "mfn_ci_roll_gate: OK #$g_id ${g_sha:0:7} docs-equivalent (latest #$run_id $status)"
    return 0
  done <<< "$green_lines"

  echo "mfn_ci_roll_gate: FAIL CI #$run_id status=$status conclusion=$conclusion (no docs-equivalent GREEN ancestor)" >&2
  return 1
}