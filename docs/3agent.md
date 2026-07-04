# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** **M2.5.6** — voter dial + hub tip wait in `start-all`; GHA health-check gate; extended rehearsal timeouts.
- **Done:** M2.5.5 (`ec845fd`); CI #512 green; Nightly #52 ignored **PASS**.
- **Next:** Push M2.5.6 → RC Validation → Nightly #53 green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-ec845fd` + RC audit dry-run (go).
- **Next:** Refresh release evidence after green Nightly on M2.5.6 commit.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Doing:** **M2.5.6** — GHA health-check gate; faucet/mined/upload/observer 420–480s windows.
- **Done:** M2.5.5 hub liveness wait + voter P2P poll.
- **Next:** Green Nightly participant + observer.

## Cross-Agent Blockers

- Nightly #52 partial (ignored pass; participant+observer fail ~6m); M2.5.6 hardening in progress.
