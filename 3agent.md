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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.86** hub poll + log dump for Nightly rehearsal. | **In progress** — ci-check running; push after green. | Monitor Nightly #49 after RC auto-dispatch. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.86** release evidence. | **Pending** — `052e507` evidence generated locally; commit with M2.4.86. | Operator sign-off after Nightly + soak. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.86** full Nightly green. | **Blocked** — rehearsal jobs fail ~3m (hub poll timeout suspected). | Confirm all 3 Nightly jobs green. |

## Recently Completed

- Agent 1: **M2.4.85** — `start-all --no-build`, preserve `SLOT_MS`; CI green on `052e507` (run 28682779428).
- Agent 1: **M2.4.84** — CI-aware timeouts + sortition smoke fix + nightly pre-build; Nightly ignored **PASS** (#47–#48).
- Agent 2: **M2.4.83** — full green CI chain on `5384ae2` + auto Nightly dispatch.
- Agent 3: Windows participant + observer rehearsal PASS (local).

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.85)

- [x] Windows 30s-slot soak PASS height 38 + RESTART.
- [x] Green GitHub CI on `052e507` (run 28682779428).
- [x] RC Validation auto-dispatch verified.
- [x] Nightly ignored P2P/produce smokes **PASS** on GitHub (#47–#48).
- [x] M2.4.85: `start-all --no-build`; preserve caller `SLOT_MS` in `config.env`.

### In Progress (M2.4.86)

- [x] Diagnose rehearsal failure timing (~3m): hub `mfnd_p2p_listening` poll likely exceeds 120s on GitHub runners.
- [x] Increase `HUB_POLL_MAX` / `OBSERVER_POLL_MAX` to **300s** on `GITHUB_ACTIONS`.
- [x] Tail `v0.log` / `observer.log` to stderr on hub/observer startup failure.
- [x] Add Nightly workflow step to dump devnet logs on rehearsal failure (visible in Actions UI).
- [x] Increase post-start wait on CI (75s no-observer, 90s with-observer).
- [ ] Local CI mirror PASS.
- [ ] Push → green CI (~70 min) → Nightly #49 via RC Validation.

### Next

- [ ] First full green Nightly (rehearsal + observer jobs).
- [ ] Linux 30s-slot soak evidence (manual **Linux Soak Audit** workflow, ~35 min).
- [ ] Archive Linux soak artifact.
- [ ] Operator sign-off on release inventory.

## Agent 3 Detailed Plan

- [x] Nightly ignored integration green on GitHub (`052e507`).
- [ ] First full green **Nightly** (rehearsal jobs — M2.4.86 hub poll fix).

## Agent 2 Detailed Plan

- [x] `release-evidence-648ae0d` + RC audit committed (`26a2d07`).
- [ ] `release-evidence-052e507` + M2.4.86 evidence after push.
- [ ] Operator human sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **PASS** (`052e507`).
- Nightly ignored suite — **PASS** (#48); rehearsal jobs — **fail** (hub poll timeout; M2.4.86 fix).
- Linux 30s-slot soak evidence — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Rehearsal Nightly jobs: hub startup exceeds 120s poll on GitHub runners (M2.4.86).
- Linux Soak Audit manual dispatch (~35 min).
- Hold pushes until M2.4.86 ci-check green; then ~70 min CI before next Nightly auto-dispatch.
