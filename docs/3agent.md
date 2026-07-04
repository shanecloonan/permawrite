# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** Monitor Nightly #52 on `ec845fd`.
- **Done:** M2.5.5 pushed; CI #512 **GREEN** (all OS); local CI mirror green.
- **Next:** Nightly #52 green → Linux soak → operator sign-off.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-ec845fd` + RC audit dry-run (go).
- **Next:** Operator sign-off after Nightly #52 green.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** M2.5.5 devnet voter readiness + hub liveness hardening.
- **Doing:** Await Nightly #52 participant+observer on `ec845fd`.
- **Next:** Onboarding polish after green Nightly.

## Cross-Agent Blockers

- Nightly #52 **IN PROGRESS** on `ec845fd` — RC gate open until all three nightly jobs pass.
