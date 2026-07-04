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

- **Done:** M2.5.13 — RC dry-run assert gate; nightly partial evidence on failure.
- **Done:** M2.5.14 — ci-check RC dry-run; nightly failure log tail.
- **Next:** Green CI #536 → Nightly #55.

## Cross-Agent Blockers

- Nightly #55 is the next gate for participant+observer smokes on M2.5.8+ stack with M2.5.12 assert gate.
