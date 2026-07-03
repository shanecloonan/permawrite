# 3agent Coordination

This file coordinates the three active Permawrite agent lanes. Keep using `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and the operator runbooks as the detailed source of truth; this file is the cross-agent handoff board for current work, completed units, and next work.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

## Update Protocol

- Update this file at the start or end of every coherent agent unit.
- Record the exact lane owner, current unit, status, blockers, and next handoff.
- Do not claim another agent's uncommitted work; mention it as "observed local work" until it lands on `main`.
- Continue updating `docs/TESTNET_CHECKLIST.md` for durable release-readiness tasks.
- Commit and push completed units to `main` after the required local CI mirror passes.

## Current Board

| Agent | Lane | Current Unit | Status | Next Handoff |
| --- | --- | --- | --- | --- |
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.64** mesh stability: sync proposal fan-out, catch-up idle skip, bounded inbound workers. | Code complete locally; CI mirror running; soak + rehearsal next. | `soak: RESTART` PASS → Agent 3 rehearsal promotion. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | GitHub CI monitor + release gates. | Monitor latest `main` after M2.4.64 push. | Archive validation on green CI. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | Participant rehearsal evidence fixture. | Blocked on Agent 1 soak/rehearsal green after M2.4.64. | Re-run `participant-rehearsal-smoke` after M2.4.64 lands. |

## Recently Completed

- Agent 1: M2.4.63 — slower catch-up intervals; atomic `devnet-ports.env`; session unregister (`619cacf` / `d46d87c`).
- Agent 1: M2.4.63 — unregister P2P sessions on post-handshake exit (`mfnd_p2p_session_unregister`).
- Agent 1: M2.4.62 — durable catch-up peers, production/tx fan-out split, producer seal-on-quorum slot tick, immediate proposal fan-out on adopt, observer catch-up gated on `--p2p-dial`, two-phase soak warmup.
- Agent 2: Release evidence, schema validation, sign-off manifests, audit packets, participant smoke CI policy.
- Agent 3: Participant rehearsal smoke, permanence index wait hardening, evidence-dir handoff.

## Agent 1 Detailed Plan

### Done (M2.4.62)

- [x] Seal pending proposals with quorum on producer slot tick.
- [x] Durable vs ephemeral peer sets for catch-up / production / tx fan-out.
- [x] Two-phase soak warmup (`soak: WARMUP phase=hub_produced` / `phase=converged`).
- [x] Observer catch-up only when `--p2p-dial` is set.
- [x] Participant rehearsal skips observer via `MFN_DEVNET_NO_OBSERVER=1`.

### Done (M2.4.63)

- [x] `unregister_session` on post-handshake loop exit (`SessionUnregisterGuard` in `mfn-net`).
- [x] Atomic `devnet-ports.env` writes via `ports-env-lib.ps1`.
- [x] Unit test `unregister_session_drops_live_session_count`.
- [x] Slower committee/observer catch-up intervals (full slot duration, min 5s / 15s).

### In progress (M2.4.64)

- [x] **`fanout_proposal_sync`** — producer adopt + slot-tick rebroadcast apply votes inline (no async race).
- [x] Extended pending release when votes > 0 (`PENDING_PROPOSAL_REBROADCAST_WITH_VOTES_LIMIT = 60`).
- [x] **`periodic_catch_up_idle`** — skip committee catch-up dials when all durable peers have live sessions.
- [x] Bounded inbound P2P worker threads (cap 48) so accept loop never blocks on post-handshake.
- [x] Unit test `periodic_catch_up_idle_when_all_durable_peers_have_sessions`.
- [ ] Local CI mirror green.
- [ ] Live `soak.ps1 -RestartObserverOnce` full PASS + `soak: RESTART` evidence.
- [ ] Participant rehearsal smoke PASS past height 5.

### Next (after soak + rehearsal green)

- [ ] Agent 3: promote participant rehearsal smoke to slow/nightly CI.
- [ ] Long-run hub daemon lifetime audit under 30s-slot public devnet config.

## Agent 3 Detailed Plan

- [x] Harden `permanence-demo` upload-index wait; 10s slot smoke defaults.
- [ ] Capture public-devnet participant evidence fixture from successful live rehearsal.
- [ ] Promote participant rehearsal smoke into slow/nightly CI once Agent 1 `soak: RESTART` is green.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI.
- Local CI mirror passed on the release host or equivalent clean machine.
- Ignored/nightly smoke coverage is run for public-devnet release candidates.
- `CODEBASE_STATS.md` regenerated after final changes.
- `release-evidence.md` and `release-evidence.json` generated for the exact commit.
- Support bundle includes valid `release-evidence.v1` JSON.
- Artifact inventory is filled, reviewed, and validated.
- Release archive is staged, checksum-validated, and reviewed as public-only.
- Security docs still say pre-audit experimental and do not imply production safety.
- RPC remains loopback/private unless a written firewall/TLS/API-key exception has an owner.

## Agent 2 Detailed Plan

- [ ] Monitor GitHub CI on M2.4.64 commit.
- [ ] Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md`.
