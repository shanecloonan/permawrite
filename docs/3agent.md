# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** **M2.5.5** — pushed; await CI + Nightly #52 on fix commit.
- **Done:** M2.5.4 ring-16 devnet scripts; CI #509 green; Nightly #51 triaged (all jobs fail).
- **Next:** RC Validation → Nightly #52 green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-9c76050` + RC audit dry-run (go) on `6936c47`.
- **Next:** Refresh release evidence after green Nightly on M2.5.5 commit.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Doing:** **M2.5.5** — pushed; hub liveness wait + voter readiness in start-all.
- **Done:** M2.5.4 devnet ring-16 defaults.
- **Next:** Green Nightly participant + observer on fix commit.

## Cross-Agent Blockers

- Nightly #51 failed (ignored flake + devnet CI liveness); M2.5.5 fix pushed — await Nightly #52.
