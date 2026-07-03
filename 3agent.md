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
| Agent 1 | Core protocol, consensus, networking, sync | M2.4.62 follow-up (`edff97b`). | Pushed; GitHub CI monitoring. | Windows full `soak: RESTART` PASS. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | Release audit packet + archive policy toolchain integration. | Completed on `main`. | Monitor GitHub CI on `cc3d2d3`. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | Live participant rehearsal evidence fixture. | Harness hardened on `main`; full smoke still flaky when hub RPC dies under observer load. | Re-run `participant-rehearsal-smoke` on `cc3d2d3`; archive evidence fixture. |

## Recently Completed

- Agent 1: M2.4.61 — restored M2.3.29 (`--produce` skips committee catch-up); helper mesh back to hub `--produce` + committee voters; hub bounded slot scan handles `F=1.5` genesis.
- Agent 1: M2.4.60 — soak converged warmup (`soak: WARMUP`), manifest multi-producer sortition bounds, P2P dial readiness timeouts.
- Agent 1: M2.4.59 — observer restart soak evidence (`soak: RESTART`).
- Agent 1: M2.4.62 — durable catch-up peers, producer seal-on-quorum slot tick, observer catch-up + inbound ahead-tip pull, two-phase soak warmup, soak SLOT_MS/stall auto-tuning.
- Agent 2: Release evidence, schema validation, sign-off manifests, audit packets, participant smoke CI policy, wheelhouse/offline validation.
- Agent 3: Participant rehearsal smoke, faucet reward wait hardening, evidence-dir release-audit handoff.

## Agent 1 Detailed Plan

Completed unit (M2.4.61):

- [x] Restore M2.3.29: `spawn_committee_catch_up_loop` only for `--committee-vote`, not `--produce`.
- [x] Revert helper mesh voters to `--committee-vote` (hub slot scan covers genesis).
- [x] Pin hub catch-up exclusion in `public_devnet_hub_reaches_height_one_within_one_slot_duration`.
- [x] Update `docs/TESTNET.md`, `OPERATORS.md`, `ROADMAP.md`, `TESTNET_CHECKLIST.md`.
- [ ] Regenerate `CODEBASE_STATS.md`, run local CI mirror, push, check GitHub CI.
- [ ] Re-run `soak.ps1 -RestartObserverOnce` and archive passing `soak: RESTART` evidence.

Completed unit (M2.4.62):

- [x] Seal pending proposals with quorum on producer slot tick when vote ingest did not apply the block.
- [x] Exclude ephemeral inbound peers from committee catch-up / reconnect / `peers.json` persist (`durable_peers` set).
- [x] Two-phase soak warmup: hub-only health (`MFN_HEALTH_REQUIRE_ALL_ROLES=0`) then full mesh convergence.
- [x] Unit test `ephemeral_peers_are_excluded_from_committee_catch_up` green.
- [x] Two-phase soak warmup passes (`soak: WARMUP phase=hub_produced` / `phase=converged`).
- [ ] Live `soak.ps1 -RestartObserverOnce` full PASS + `soak: RESTART` (RPC refused / stall tuning on 30s-slot Windows host).
- [x] Regenerate `CODEBASE_STATS.md`, commit, push (`edff97b`); check GitHub CI.

Next Agent 1 task:

- [ ] Investigate any remaining hub daemon lifetime issues under long soak runs.

## Agent 3 Detailed Plan

Completed unit:

- [x] Harden `permanence-demo` upload-index wait with `hub_tip_height` logging and 120s stall fail-fast.
- [x] Use 10s smoke slot duration (`SLOT_MS=10000`) and 360s upload wait in participant rehearsal smoke.

Next Agent 3 task:

- [ ] Capture public-devnet participant evidence fixture from successful live `participant-rehearsal-smoke`.
- [ ] Promote participant rehearsal smoke into slow/nightly CI once Agent 1 soak `soak: RESTART` evidence is green.

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

Next Agent 2 task:

- [ ] Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md` (next unchecked Agent 2 item).
