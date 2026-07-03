# 3agent Coordination

This file coordinates the three active Permawrite agent lanes. Keep using `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and the operator runbooks as the detailed source of truth; this file is the cross-agent handoff board for current work, completed units, and next work.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

## Update Protocol

- Update this file at the start or end of every coherent agent unit.
- Record the exact lane owner, current unit, status, blockers, and next handoff.
- Do not claim another agent's uncommitted work; mention it as "observed local work" until it lands on `main`.
- Continue updating `docs/TESTNET_CHECKLIST.md` for durable release-readiness tasks.
- Commit and push completed units to `main` after the required local CI mirror passes.
- **Do not push while CI is in progress** — concurrency `cancel-in-progress` aborts the matrix (~70 min on Linux/macOS).

## Current Board

| Agent | Lane | Current Unit | Status | Next Handoff |
| --- | --- | --- | --- | --- |
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.85** rehearsal `start-all --no-build`. | **In progress** — fix redundant mfnd rebuild on Nightly; local ci-check. | Green Nightly after M2.4.85 CI + RC dispatch. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.84** release evidence `648ae0d`. | **Done** — CI green run 28677784928; evidence + RC audit archived locally. | Regenerate for M2.4.85 after CI green. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.84–85** Nightly rehearsal. | **Partial** — Nightly #47 ignored suite **PASS**; rehearsal jobs failed (~2m, start-all rebuild). | Green all 3 Nightly jobs after M2.4.85. |

## Recently Completed

- Agent 1: **M2.4.84** — CI **success** on `648ae0d`; RC Validation **success**; Nightly ignored integration **PASS** (#47).
- Agent 1: **M2.4.84** — CI-aware timeouts + sortition smoke fix + nightly pre-build.
- Agent 2: **M2.4.83** — full green CI chain on `5384ae2` + auto Nightly dispatch.
- Agent 3: Windows participant + observer rehearsal PASS (local).

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.84)

- [x] Windows 30s-slot soak PASS height 38 + RESTART.
- [x] Green GitHub CI on `648ae0d` (run 28677784928).
- [x] RC Validation auto-dispatch verified.
- [x] Nightly ignored P2P/produce smokes **PASS** on GitHub (#47).

### In Progress (M2.4.85)

- [x] Diagnose rehearsal failure: `start-all.sh` rebuilds mfnd despite smoke `--no-build`; `config.env` overwrote Nightly `SLOT_MS=10000`.
- [x] Add `start-all.sh --no-build`; wire from `participant-rehearsal-smoke.sh`.
- [x] Preserve caller `SLOT_MS` in `config.env` (`: "${SLOT_MS:=30000}"`).
- [ ] Local CI mirror PASS + push.
- [ ] Green Nightly (rehearsal + observer jobs).
- [ ] Linux 30s-slot soak evidence.

### Next

- [ ] Archive Linux soak artifact.
- [ ] Operator sign-off on release inventory.

## Agent 3 Detailed Plan

- [x] Nightly ignored integration green on GitHub (`648ae0d`).
- [ ] First full green **Nightly** (rehearsal jobs pending M2.4.85).

## Agent 2 Detailed Plan

- [x] `release-evidence-648ae0d` + RC audit decision=go (local).
- [ ] Commit evidence to `main` with M2.4.85.
- [ ] Operator human sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **PASS** (`648ae0d`).
- Nightly ignored suite — **PASS** (#47); rehearsal jobs — **fail** (M2.4.85 fix).
- Linux 30s-slot soak evidence — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Rehearsal Nightly jobs need `start-all --no-build` when binaries pre-built (M2.4.85).
- Linux Soak Audit manual dispatch (~35 min).
- Hold pushes until M2.4.85 ci-check green; then ~70 min CI before next Nightly auto-dispatch.
