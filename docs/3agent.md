# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **Doing:** M2.4.84 Nightly GitHub runner hardening (timeouts, pre-build, log artifacts).
- **Done:** Local ci-check PASS; clippy PASS on mfn-node.
- **Next:** Green CI + Nightly re-run; Linux Soak Audit dispatch.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Waiting:** M2.4.84 CI green; regenerate release-evidence.
- **Done:** `release-evidence-5384ae2` + RC audit decision=go.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **Blocked:** Nightly #46 failed (~2m, all jobs).
- **Next:** First green Nightly (ignored + both rehearsal jobs) after M2.4.84.

## Cross-Agent Blockers

- Nightly failure likely runner startup timeouts — M2.4.84 fix in flight.
- Linux Soak Audit still manual (~35 min).
