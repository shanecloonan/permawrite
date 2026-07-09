#!/usr/bin/env bash
# Dispatch release-candidate validation workflows on GitHub Actions (requires gh auth).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

REF=main
CHECKOUT_SHA=""
SLOT_MS=30000
DURATION_MINUTES=35
MIN_FINAL_HEIGHT=10
DISPATCH_NIGHTLY=0
DISPATCH_SOAK=0

usage() {
  cat <<'USAGE'
usage: dispatch-rc-workflows.sh [--ref BRANCH] [--checkout-sha SHA] [--nightly] [--linux-soak-audit] [--all]
       [--slot-ms MS] [--duration-minutes N] [--min-final-height N]

Requires: gh auth login

Defaults (no flags): dispatch both Nightly and Linux Soak Audit on main.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) REF="${2:?}"; shift 2 ;;
    --checkout-sha) CHECKOUT_SHA="${2:?}"; shift 2 ;;
    --nightly) DISPATCH_NIGHTLY=1; shift ;;
    --linux-soak-audit) DISPATCH_SOAK=1; shift ;;
    --all) DISPATCH_NIGHTLY=1; DISPATCH_SOAK=1; shift ;;
    --slot-ms) SLOT_MS="${2:?}"; shift 2 ;;
    --duration-minutes) DURATION_MINUTES="${2:?}"; shift 2 ;;
    --min-final-height) MIN_FINAL_HEIGHT="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; echo "dispatch-rc-workflows: unknown argument $1" >&2; exit 1 ;;
  esac
done

if (( DISPATCH_NIGHTLY == 0 && DISPATCH_SOAK == 0 )); then
  DISPATCH_NIGHTLY=1
  DISPATCH_SOAK=1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "dispatch-rc-workflows: install GitHub CLI (gh) and run 'gh auth login'" >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "dispatch-rc-workflows: gh not authenticated. Run: gh auth login" >&2
  exit 1
fi

if (( DISPATCH_NIGHTLY == 1 )); then
  if [[ -z "$CHECKOUT_SHA" ]]; then
    CHECKOUT_SHA="$(git rev-parse HEAD)"
  elif [[ ${#CHECKOUT_SHA} -lt 40 ]]; then
    CHECKOUT_SHA="$(git rev-parse "$CHECKOUT_SHA")"
  fi
  echo "dispatch-rc-workflows: triggering Nightly on ref=$REF checkout_sha=$CHECKOUT_SHA"
  gh workflow run nightly.yml --ref "$REF" -f "checkout_sha=$CHECKOUT_SHA"
fi

if (( DISPATCH_SOAK == 1 )); then
  echo "dispatch-rc-workflows: triggering Linux Soak Audit on ref=$REF (SLOT_MS=$SLOT_MS duration=${DURATION_MINUTES}m min_height=$MIN_FINAL_HEIGHT)"
  gh workflow run linux-soak-audit.yml --ref "$REF" \
    -f "slot_ms=$SLOT_MS" \
    -f "duration_minutes=$DURATION_MINUTES" \
    -f "min_final_height=$MIN_FINAL_HEIGHT"
fi

owner_repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
echo "dispatch-rc-workflows: OK — monitor https://github.com/${owner_repo}/actions"
