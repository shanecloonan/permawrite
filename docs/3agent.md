# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Done:** M2.4.79 UTF-8 guard; CI queue cleanup **success** on `b581e78`.
- **Doing:** Monitor CI `6685c79`.
- **Next:** Linux Soak Audit manual dispatch.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Done:** `release-evidence-b581e78` + RC audit decision=go.
- **Doing:** Monitor GitHub CI green.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Waiting:** RC validation dispatches Nightly when CI passes.
- **Next:** Confirm Nightly green + archived Linux rehearsal evidence.

## Cross-Agent Blockers

- None — queue cleanup fixed. Awaiting CI completion.
