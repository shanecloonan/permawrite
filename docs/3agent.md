# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** **M2.5.7** — Nightly #53 participant/observer fix (voter dial + health-check retry).
- **Done:** M2.5.6 (`f5f45bf`) — CI #514 **GREEN**; Nightly #53 ignored **PASS**.
- **Next:** Push M2.5.7 → CI green → RC Validation → Nightly #54.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-f5f45bf` + RC audit dry-run (go).
- **Next:** Refresh evidence after green Nightly on M2.5.7 commit.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Doing:** **M2.5.7** — 420s health-check retry; `MIN_P2P_SESSIONS=1` on GHA.
- **Done:** M2.5.6 voter dial + hub tip wait in `start-all`.
- **Next:** Green Nightly participant + observer.

## Cross-Agent Blockers

- Nightly #53 **FAIL** on `f5f45bf` (participant+observer ~6m); M2.5.7 fix pushing.
