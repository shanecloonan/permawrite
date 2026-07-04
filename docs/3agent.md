# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** RC Validation → Nightly #50 after CI #505 green on `95739e4`.
- **Done:** M2.5.3 pushed; CI #505 green (all OS).
- **Next:** RC Validation → Nightly #50.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** `release-evidence-95739e4` + RC audit dry-run.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Done:** M2.5.3 mempool/mfnd/runtime ring-16 harness.
- **Next:** Nightly #50 after CI green.

## Cross-Agent Blockers

- CI #505 green — proceed with RC Validation and Nightly #50.
