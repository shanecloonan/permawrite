# Three-Agent Coordination Checklist

See the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Agent 1: Core Protocol, Consensus, Networking, Sync

- **M2.4.70 done:** soak lock + ports snapshot; 30s-slot 35min PASS (height 38, observer RESTART).
- **M2.4.71 done:** soak `-MinFinalHeight` / graceful deadline exit / archive on finish.
- Evidence: `scripts/public-devnet-v1/evidence/soak-restart-windows-30s-slot-20260703T132240Z.txt`.

## Agent 2: Security, RPC, Ops, Release Readiness

- **M2.4.72 done:** `release-evidence` JSON/MD for commit `ebe1e48` in `evidence/release-evidence-ebe1e48.*`.
- **Next:** `release-audit-packet` dry-run after CI green.

## Agent 3: Wallet, Storage, Faucet, Onboarding

- **M2.4.72 done:** nightly job `participant-rehearsal-smoke-observer` (Linux, 10s slots, hub≥5).
- **Next:** Confirm first green Linux nightly for both rehearsal jobs.

## Cross-Agent Blockers

- `gh` not authenticated locally; use GitHub Actions UI or unauthenticated API for CI status.
- Release archive validation pending green CI on M2.4.71–72 push.
