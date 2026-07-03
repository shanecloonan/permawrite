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

- **M2.4.63** hub P2P + production fan-out hardening (in progress).

Done this unit:

- Async inbound P2P handlers with concurrency cap (48).
- Durable-only proposal/vote fan-out; session bootstrap before advertise.
- Ephemeral inbound dialers no longer pollute the durable peer set.
- Immediate proposal fan-out when producer adopts a pending block.
- Slower committee/observer catch-up intervals.
- Participant rehearsal smoke skips observer (`MFN_DEVNET_NO_OBSERVER=1`).
- Unregister live P2P sessions on post-handshake exit (`mfnd_p2p_session_unregister`).

Next:

- Skip committee catch-up when already synced to durable peers.
- Fix height >= 5 quorum / hub exit under sustained catch-up load.
- Windows `soak.ps1 -RestartObserverOnce` evidence.

## Agent 2: Security, RPC, Ops, Release Readiness

Current:

- Monitor GitHub CI on M2.4.63.

Next:

- Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md`.

## Agent 3: Wallet, Storage, Faucet, Onboarding

Current:

- Re-run full `participant-rehearsal-smoke` after Agent 1 height-5 fix.

Done this unit:

- `fund-wallet` PASS on M2.4.63 runs reaching height >= 2.
- Harness hardening (hub tip logging, stall fail-fast, build-before-start).

Next:

- Archive participant evidence fixture from a green rehearsal run.
- Promote rehearsal smoke to slow/nightly CI after soak RESTART evidence.
