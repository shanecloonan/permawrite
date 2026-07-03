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

- **M2.4.63** hub accept-loop hardening (remaining): bounded inbound post-handshake workers, catch-up skip when synced, hub lifetime past height 5.

Done (M2.4.62 — `cc3d2d3` / `edff97b`):

- Durable-only proposal/vote fan-out with live-session bootstrap before advertise.
- Ephemeral inbound dialers excluded from durable catch-up and production fan-out.
- Immediate proposal fan-out when producer adopts a pending block.
- Participant rehearsal smoke skips observer (`MFN_DEVNET_NO_OBSERVER=1`).
- Two-phase soak warmup; observer catch-up gated on `--p2p-dial`.

Done (M2.4.63 — `619cacf`):

- Unregister live P2P sessions on post-handshake exit (`mfnd_p2p_session_unregister`).
- Unit test `unregister_session_drops_live_session_count`.

In progress (M2.4.63 follow-up — uncommitted):

- Atomic `devnet-ports.env` rewrite via `ports-env-lib.ps1` (fixes soak `HUB_PID missing` from partial writes).
- Windows `soak.ps1 -RestartObserverOnce` evidence capture.

Next:

- Offload inbound post-handshake loops to bounded worker threads (accept loop must not block on catch-up).
- Skip committee catch-up when already synced to durable peers.
- Fix height >= 5 quorum / hub exit under sustained catch-up load.
- Windows `soak.ps1 -RestartObserverOnce` evidence.

## Agent 2: Security, RPC, Ops, Release Readiness

Current:

- Monitor GitHub CI on `619cacf` / latest `main`.

Next:

- Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

Current:

- Re-run full `participant-rehearsal-smoke` after Agent 1 hub-lifetime + soak fixes.

Done this unit:

- `fund-wallet` PASS on M2.4.62/M2.4.63 runs reaching height >= 2.
- Permanence-demo upload-index wait hardening; 10s slot smoke defaults.

Next:

- Capture public-devnet participant evidence fixture from successful live rehearsal.
- Promote participant rehearsal smoke into slow/nightly CI once Agent 1 `soak: RESTART` is green.

## Cross-Agent Blockers

- Agent 3 nightly promotion remains blocked until Agent 1 archives passing `soak: RESTART` and hub lifetime past height 5 is stable.
- Agent 2 finished hash-pinned release-schema installs, offline wheelhouse helpers, release-archive wheelhouse staging/validation, and participant rehearsal smoke CI policy guard for air-gapped strict validation and flaky-mesh CI safety.
