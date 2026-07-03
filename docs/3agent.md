# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **M2.4.69 in progress:** 30s-slot (`SLOT_MS=30000`) hub lifetime soak with `-ArchiveEvidence` (35 min, observer restart).
- Done: M2.4.66–68 mesh stability, soak RESTART (10s), observer rehearsal height 5.

## Agent 2: Security, RPC, Ops, Release Readiness

- Generate release-evidence after M2.4.69 soak green.
- Monitor GitHub CI + nightly rehearsal job.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- Confirm Linux nightly `participant-rehearsal-smoke` green (workflow live since M2.4.67).

## Cross-Agent Blockers

- Release-evidence packet blocked on M2.4.69 30s-slot soak evidence (Agent 1).
