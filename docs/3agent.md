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

- **M2.4.64** mesh stability under catch-up load (uncommitted → landing):
  - Sync proposal fan-out on producer adopt + slot-tick rebroadcast (`fanout_proposal_sync`).
  - Extended pending release when votes exist (`PENDING_PROPOSAL_REBROADCAST_WITH_VOTES_LIMIT = 60`).
  - Skip committee catch-up when all durable peers have live sessions (`periodic_catch_up_idle`).
  - Bounded inbound P2P post-handshake workers (cap 48) so accept loop never blocks.

Done (M2.4.63 — `d46d87c`):

- Slower committee/observer catch-up intervals.
- Atomic `devnet-ports.env` rewrite via `ports-env-lib.ps1`.
- Unregister live P2P sessions on post-handshake exit (`619cacf`).

Done (M2.4.62 — `cc3d2d3` / `edff97b`):

- Durable-only proposal/vote fan-out with live-session bootstrap before advertise.
- Ephemeral inbound dialers excluded from durable catch-up and production fan-out.
- Immediate proposal fan-out when producer adopts a pending block.
- Participant rehearsal smoke skips observer (`MFN_DEVNET_NO_OBSERVER=1`).
- Two-phase soak warmup; observer catch-up gated on `--p2p-dial`.

Next:

- Windows `soak.ps1 -RestartObserverOnce` evidence after M2.4.64 CI green.
- Participant rehearsal smoke PASS past height 5 (Agent 3 re-run).

## Agent 2: Security, RPC, Ops, Release Readiness

Current:

- Monitor GitHub CI on M2.4.64 commit after push.

Next:

- Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

Current:

- Re-run full `participant-rehearsal-smoke` after Agent 1 M2.4.64 lands.

Done this unit:

- `fund-wallet` PASS on M2.4.62/M2.4.63 runs reaching height >= 2.
- Permanence-demo upload-index wait hardening; 10s slot smoke defaults.

Next:

- Capture public-devnet participant evidence fixture from successful live rehearsal.
- Promote participant rehearsal smoke into slow/nightly CI once Agent 1 `soak: RESTART` is green.

## Cross-Agent Blockers

- Agent 3 nightly promotion remains blocked until Agent 1 archives passing `soak: RESTART` and participant rehearsal smoke passes end-to-end.
- Prior root cause (pre-M2.4.64): catch-up dial storms blocked accept loop; async proposal fan-out raced vote ingest; pending released too early with partial votes → stale `header_hash` rejections at height 5+.
