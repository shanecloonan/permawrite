# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** Monitor Nightly #49 on `95739e4`.
- **Done:** M2.5.3 pushed; CI #505 all-OS green.
- **Next:** Linux soak audit; operator sign-off.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-95739e4` + RC audit dry-run (decision=go).
- **Next:** Operator sign-off after Nightly #49.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** M2.5.3 mempool/mfnd/runtime ring-16 harness.
- **Next:** Nightly #49 green.

## Cross-Agent Blockers

- Nightly #49 in flight — monitor participant + observer rehearsal on `95739e4`.
