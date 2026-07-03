# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.83 RC validation nightly dispatch ref fix.
- **Done:** M2.4.82 full green CI on `e6e8d86`; queue cleanup preserves current commit.
- **Next:** Linux Soak Audit after Nightly green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Push M2.4.83 + archived `release-evidence-e6e8d86`.
- **Done:** RC audit dry-run decision=go for `e6e8d86` (CI run 28670552593).
- **Next:** Confirm Nightly dispatch after M2.4.83.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Blocked:** RC Validation #12 failed — `No ref found for` commit SHA.
- **Next:** Nightly green + Linux soak evidence once M2.4.83 lands.

## Cross-Agent Blockers

- GitHub `createWorkflowDispatch` requires branch/tag ref, not raw SHA — **M2.4.83** fix ready.
- Optional: manual **RC Validation After CI** `workflow_dispatch` with `ci_head_sha=e6e8d86` after push.
