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
| Agent 1 | Core protocol, consensus, networking, sync | Public-devnet hub liveness integration smoke (`75eb64d`). | Complete on `main`; GitHub CI run #445 in progress. | Hand mesh stability evidence to Agent 3. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | Release audit packet + archive policy toolchain integration. | Completed on `main`. | Monitor GitHub CI; review Agent 3 rehearsal harness fixes. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | Rehearsal smoke harness + permanence indexing on live mesh. | In progress — fund-wallet PASS after build-before-start fix; permanence index wait still flaky at height stall. | Fix permanence-demo index wait / mesh tip diagnostics; capture evidence fixture. |

## Recently Completed

- Agent 1: M2.4.61 — restored M2.3.29 (`--produce` skips committee catch-up); helper mesh back to hub `--produce` + committee voters; hub bounded slot scan handles `F=1.5` genesis.
- Agent 1: M2.4.60 — soak converged warmup (`soak: WARMUP`), manifest multi-producer sortition bounds, P2P dial readiness timeouts.
- Agent 1: M2.4.59 — observer restart soak evidence (`soak: RESTART`).
- Agent 1: Bounded in-tick producer slot scan + `public_devnet_hub_reaches_height_one_within_one_slot_duration` integration smoke.
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

Next Agent 1 task:

- [ ] Live observer restart soak evidence on Windows.
- [ ] Investigate any remaining hub daemon lifetime issues under long soak runs.

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

## Agent 3 Detailed Plan

Next Agent 3 task:

- [ ] Promote participant rehearsal smoke into slow/nightly CI once Agent 1 soak `soak: RESTART` evidence is green.
