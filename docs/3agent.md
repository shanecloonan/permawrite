# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.79 UTF-8 workflow guard + fix ci-queue-cleanup regression.
- **Done:** M2.4.78 RC validation + Nightly archive evidence wiring.
- **Next:** Linux Soak Audit dispatch after CI green.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Doing:** Monitor CI; release-evidence for green commit.
- **Next:** RC audit dry-run for latest green SHA.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Waiting:** RC validation auto-dispatch Nightly when CI passes.
- **Next:** Confirm Nightly green + archived Linux rehearsal evidence.

## Cross-Agent Blockers

- UTF-16 workflow regression on `2342b75` blocked queue cleanup — M2.4.79 fix in flight.
