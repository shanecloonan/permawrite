# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.81 CI `workflow_dispatch` + re-trigger full CI matrix.
- **Done:** M2.4.80 validate fix; public-devnet scripts green on GitHub.
- **Next:** Linux Soak Audit dispatch after CI green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** `release-evidence-2497668` + `rc-audit-dry-run-2497668-20260703T152900Z.json` decision=go archived.
- **Next:** Confirm GitHub CI green; operator sign-off.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Waiting:** RC validation auto-dispatch Nightly when full CI passes.
- **Next:** Confirm Nightly green + Linux soak evidence archived.

## Cross-Agent Blockers

- Unauthenticated GitHub API rate limit — use Actions UI or `GH_TOKEN`.
- Full CI on `2497668` cancelled mid-test; M2.4.81 push re-triggers.
