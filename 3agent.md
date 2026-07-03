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
| Agent 1 | Core protocol, consensus, networking, sync | M2.4.63 P2P session unregister on disconnect. | In progress — unit test green; live soak running. | Full `soak: RESTART` PASS → Agent 3. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | Release audit packet + archive policy toolchain integration. | Completed on `main`. | Monitor GitHub CI on latest `main`. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | Participant rehearsal evidence fixture. | Harness hardened (`MFN_DEVNET_NO_OBSERVER`); blocked on Agent 1 soak. | Re-run `participant-rehearsal-smoke` after soak green. |

## Recently Completed

- Agent 1: M2.4.62 — durable catch-up peers, production/tx fan-out split, producer seal-on-quorum slot tick, immediate proposal fan-out on adopt, observer catch-up gated on `--p2p-dial`, two-phase soak warmup, soak `SLOT_MS`/stall auto-tuning (`edff97b` / `9520243`).
- Agent 1: M2.4.61 — restored M2.3.29; hub `--produce` + committee voters; bounded hub slot scan.
- Agent 1: M2.4.60 — soak converged warmup, manifest multi-producer sortition bounds.
- Agent 2: Release evidence, schema validation, sign-off manifests, audit packets, participant smoke CI policy.
- Agent 3: Participant rehearsal smoke, permanence index wait hardening, evidence-dir handoff.

## Agent 1 Detailed Plan

### Done (M2.4.62)

- [x] Seal pending proposals with quorum on producer slot tick.
- [x] Durable vs ephemeral peer sets for catch-up / production / tx fan-out.
- [x] Two-phase soak warmup (`soak: WARMUP phase=hub_produced` / `phase=converged`).
- [x] Observer catch-up only when `--p2p-dial` is set.
- [x] Participant rehearsal skips observer via `MFN_DEVNET_NO_OBSERVER=1`.

### In progress (M2.4.63)

- [x] `unregister_session` on post-handshake loop exit (`SessionUnregisterGuard` in `mfn-net`).
- [x] Unit test `unregister_session_drops_live_session_count`.
- [ ] Live `soak.ps1 -RestartObserverOnce` full PASS + `soak: RESTART` evidence.
- [ ] Local CI mirror green; commit, push, verify GitHub CI.

### Next (after soak green)

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

- [ ] Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md` (next unchecked Agent 2 item).
