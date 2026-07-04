# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** Monitor CI #514 on `f5f45bf`; then RC Validation → Nightly #53.
- **Done:** M2.5.6 (`f5f45bf`) — voter dial + hub tip wait; local CI mirror green.
- **Next:** CI #514 green → RC Validation → Nightly #53 green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-ec845fd` + RC audit dry-run (go).
- **Next:** Refresh release evidence after green Nightly on M2.5.6 commit.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** M2.5.6 (`f5f45bf`) — GHA health-check gate; faucet/mined/upload/observer 420–480s windows.
- **Next:** Green Nightly participant + observer on `f5f45bf`.

## Cross-Agent Blockers

- Nightly #52 partial (ignored pass; participant+observer fail ~6m); M2.5.6 hardening in progress.
