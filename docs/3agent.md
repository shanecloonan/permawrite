# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **M2.4.70 in progress:** soak lock + ports snapshot recovery; re-run 30s-slot 35min soak with `-ArchiveEvidence`.
- **M2.4.69 partial:** first 30s soak failed when `devnet-ports.env` deleted mid-run (parallel mesh start).

## Agent 2: Security, RPC, Ops, Release Readiness

- Generate release-evidence after M2.4.70 soak green + CI mirror.
- Monitor GitHub CI + nightly rehearsal job.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- Confirm Linux nightly `participant-rehearsal-smoke` green (workflow live since M2.4.67).

## Cross-Agent Blockers

- Release-evidence packet blocked on M2.4.70 30s-slot soak evidence (Agent 1).
