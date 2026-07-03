# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.85 `start-all --no-build` for Nightly rehearsal jobs.
- **Done:** Nightly ignored suite PASS on `648ae0d`; CI green run 28677784928.
- **Next:** Push M2.4.85 → CI → Nightly re-run via RC Validation.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Commit `release-evidence-648ae0d` with M2.4.85.
- **Done:** RC audit decision=go for `648ae0d`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Partial:** Ignored Nightly PASS; rehearsal blocked on start-all rebuild (M2.4.85 fix ready).
- **Next:** Full green Nightly after M2.4.85 lands.

## Cross-Agent Blockers

- ~70 min CI per push before next auto Nightly.
- Linux Soak Audit still manual.
