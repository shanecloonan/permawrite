# Three-Agent Coordination Checklist

This file coordinates the three Permawrite build lanes. Keep it current alongside
`docs/TESTNET_CHECKLIST.md`; the checklist tracks milestone completion, while this
file tracks who is actively doing what, what is done, and what should happen next.

See also the root [`3agent.md`](../3agent.md) board for the latest cross-agent handoff table.

## Operating Rules

- Pull latest `main` before starting new work when the tree is safe to update.
- Do not overwrite another agent's uncommitted work.
- Keep changes scoped to the active lane unless a cross-lane blocker prevents progress.
- Update this file whenever an agent starts a unit, ships it, discovers a blocker, or hands off work.
- Before pushing `main`, run the local CI mirror and then inspect GitHub CI.

## Agent 1: Core Protocol, Consensus, Networking, Sync

Current:

- **M2.4.66** shipped: devnet-ports mutex/merge, mesh startup isolation, archived Windows soak PASS.

Done (M2.4.66):

- Mutex + merge-from-disk `Set-DevnetPort`; `stop-all` no longer deletes ports by default.
- Soak foreign-`mfnd` preflight warning; iteration budget matches stall sampling.
- Windows `soak.ps1 -RestartObserverOnce` SUMMARY PASS (611s, 5 iterations, height 28, observer restart catch-up).
- Evidence: `scripts/public-devnet-v1/evidence/soak-restart-windows-20260703T120117Z.txt`.

Next:

- Agent 3 nightly rehearsal promotion.
- 30s-slot long-run hub lifetime audit.

## Agent 2: Security, RPC, Ops, Release Readiness

Current:

- Monitor GitHub CI on M2.4.66 commit.

Next:

- Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

Current:

- **Participant rehearsal smoke PASS** on M2.4.64 (`20260703T113642Z` bundle). Agent 1 soak green — promotion unblocked.

Next:

- Capture public-devnet participant evidence fixture.
- Promote participant rehearsal smoke into slow/nightly CI.

## Cross-Agent Blockers

- None for Agent 3 nightly promotion (soak RESTART evidence archived).
