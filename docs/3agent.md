# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** Monitor Nightly #51 on `9c76050` (M2.5.4 devnet ring-16 defaults).
- **Done:** M2.5.4 CI #509 green; RC Validation #39 dispatched Nightly #51.
- **Next:** Full green Nightly (participant + observer + ignored).

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-9c76050` + RC audit dry-run (go).
- **Next:** Operator sign-off after Nightly green.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** M2.5.4 devnet fund-wallet/participant-rehearsal ring-16 defaults.
- **Next:** Nightly participant+observer green on #51.

## Cross-Agent Blockers

- Nightly #49/#50 failed on pre-fix ring-size 8; M2.5.4 fix landed; Nightly #51 in progress.
