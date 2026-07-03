# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **M2.4.70 done:** soak lock + ports snapshot; 30s-slot 35min PASS (height 38, observer RESTART).
- Evidence: `scripts/public-devnet-v1/evidence/soak-restart-windows-30s-slot-20260703T132240Z.txt`.

## Agent 2: Security, RPC, Ops, Release Readiness

- **Next:** `release-evidence.ps1` for M2.4.70 commit after CI mirror green.
- Monitor GitHub CI + nightly rehearsal job.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- Confirm Linux nightly `participant-rehearsal-smoke` green (workflow live since M2.4.67).

## Cross-Agent Blockers

- Release-evidence packet unblocked on soak evidence; pending CI + release-evidence generation.
