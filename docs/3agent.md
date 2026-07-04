# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** Monitor Nightly #53 on `f5f45bf`.
- **Done:** M2.5.6 (`f5f45bf`) — CI #514 **GREEN** (all OS); RC Validation #44 dispatched Nightly #53.
- **Next:** Full green Nightly #53 (ignored + participant + observer).

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-f5f45bf` + RC audit dry-run (go).
- **Next:** Operator sign-off after Nightly #53 green.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** M2.5.6 (`f5f45bf`) — GHA health-check gate; extended rehearsal timeouts.
- **Next:** Green Nightly participant + observer on `f5f45bf`.

## Cross-Agent Blockers

- Nightly #53 in progress on `f5f45bf`; all three jobs must pass for RC gate.
