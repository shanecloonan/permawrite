# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.82 CI Queue Cleanup preserves current-commit CI (`context.sha`).
- **Done:** M2.4.81 workflow_dispatch + wasm-pack fix; public-devnet scripts green.
- **Next:** Wait for full green CI; then Linux Soak Audit.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Hold for first fully green CI (prior runs cancelled by follow-up pushes).
- **Done:** `release-evidence-2497668` + RC audit decision=go.
- **Next:** Release-evidence for green M2.4.82 commit; operator sign-off.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Waiting:** RC validation auto-dispatch Nightly when full CI passes (push or workflow_dispatch).
- **Next:** Confirm Nightly green + Linux soak evidence archived.

## Cross-Agent Blockers

- Do not push docs-only commits while CI is running — concurrency cancels the matrix.
- Unauthenticated GitHub API rate limit — use Actions UI or `GH_TOKEN` for dispatch.