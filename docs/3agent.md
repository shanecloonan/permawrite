# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Done:** M2.5.8 — 600s GHA startup polls; Nightly #54 post-mortem.
- **Done:** M2.5.9 — shared `query_tip_height` on `main`.
- **Next:** Green Nightly #55 → Linux soak → operator sign-off.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-f5f45bf` + RC audit dry-run (go).
- **Next:** Refresh evidence after green CI + Nightly on current RC commit.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** M2.5.11 — nightly artifact upload for audit-ready smoke evidence; TESTNET.md handoff docs.
- **Next:** Green CI on push → Nightly #55 participant+observer.

## Cross-Agent Blockers

- Await green CI #529 on `f6bac5e` before next push (cancel-in-progress).
- Nightly #55 is the next gate for participant+observer smokes on M2.5.8+ stack.
