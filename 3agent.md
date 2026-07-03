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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.87** CI retry. | **Fixing** — CI #490 on `7008d0a` failed ubuntu/macOS tests (scripts-only commit; likely flake). M2.4.87 Windows parity ready. | Green CI → Nightly #49. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.86** evidence. | **Done** — `052e507` evidence committed. | `release-evidence-7008d0a` after CI green. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.86** Nightly. | **Blocked** — #48 rehearsal fail on `052e507`; hub poll 300s in `7008d0a` awaiting green CI. | All 3 Nightly jobs green on #49. |

## Recently Completed

- Agent 1: **M2.4.86** — pushed `7008d0a`; CI #490 **failed** ubuntu/macOS (14m, exit 101; no Rust changes).
- Agent 1: **M2.4.85** — `start-all --no-build`, preserve `SLOT_MS`; CI green on `052e507`.
- Agent 1: **M2.4.84** — CI-aware timeouts + sortition fix; Nightly ignored **PASS** (#47–#48).
- Agent 3: Windows participant + observer rehearsal PASS (local).

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.86)

- [x] Windows 30s-slot soak PASS height 38 + RESTART.
- [x] Green GitHub CI on `052e507` (run 28682779428).
- [x] RC Validation auto-dispatch verified.
- [x] Nightly ignored P2P/produce smokes **PASS** on GitHub (#47–#48).
- [x] M2.4.85: `start-all --no-build`; preserve caller `SLOT_MS` in `config.env`.
- [x] M2.4.86: hub/observer poll 300s; tail logs on failure; Nightly log dump step.
- [x] Local CI mirror PASS (ci-check-m286.log).
- [x] Push → `7008d0a` on `main`.

### In Progress

- [ ] Green CI on `7008d0a` or M2.4.87 retry (CI #490 failed ubuntu/macOS — likely flake).
- [ ] Push M2.4.87 (Windows start-all parity + hub poll progress logs).
- [ ] Green Nightly #49 via RC Validation after CI green.

### Next

- [ ] First full green Nightly (rehearsal + observer jobs).
- [ ] `release-evidence-7008d0a` + RC audit dry-run.
- [ ] Linux 30s-slot soak evidence (manual **Linux Soak Audit** workflow, ~35 min).
- [ ] Operator sign-off on release inventory.

## Agent 3 Detailed Plan

- [x] Nightly ignored integration green on GitHub (`052e507`).
- [ ] First full green **Nightly** (rehearsal jobs — M2.4.86 hub poll fix; #48 failed at ~193s = pre-build + 120s poll).

## Agent 2 Detailed Plan

- [x] `release-evidence-052e507` + RC audit committed with M2.4.86.
- [ ] `release-evidence-7008d0a` after CI green.
- [ ] Operator human sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **FAIL** on `7008d0a` (#490 ubuntu/macOS); **PASS** on `052e507`.
- Nightly ignored suite — **PASS** (#48); rehearsal jobs — **fail** on `052e507` (~3m13s, hub poll timeout).
- Linux 30s-slot soak evidence — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- CI run 28685902229 must complete before next push or Nightly #49 dispatch.
- Rehearsal Nightly: hub startup exceeded 120s poll on GitHub (#48 timing confirms); M2.4.86 raises to 300s.
- Observed local (uncommitted): Windows `start-all.ps1 -NoBuild` + GHA hub poll parity; bash hub poll progress logs — ship as M2.4.87 **after** CI/Nightly #49, not during CI.
