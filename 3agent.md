# 3agent Coordination

This file coordinates the three active Permawrite agent lanes. Keep using `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and the operator runbooks as the detailed source of truth; this file is the cross-agent handoff board for current work, completed units, and next work.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

## Update Protocol

- Update this file at the start or end of every coherent agent unit.
- Record the exact lane owner, current unit, status, blockers, and next handoff.
- Do not claim another agent's uncommitted work; mention it as "observed local work" until it lands on `main`.
- Continue updating `docs/TESTNET_CHECKLIST.md` for durable release-readiness tasks.
- Commit and push completed units to `main` after the required local CI mirror passes.
- **Do not push docs-only follow-ups while CI is in progress** — concurrency `cancel-in-progress` aborts the matrix before tests finish (Linux/macOS release tests often take 45–75 minutes).

## Current Board

| Agent | Lane | Current Unit | Status | Next Handoff |
| --- | --- | --- | --- | --- |
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.85** Nightly rehearsal CI hardening. | **In progress** — local `nightly.yml` pre-build + log artifacts; await CI on `8d73e36`. | Linux Soak Audit after Nightly green. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.84** release evidence chain. | **Done** — `5384ae2` CI green + RC Validation success; `1398cbf` evidence archived. | Regenerate evidence for `8d73e36` after CI green. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.84–85** first green Nightly. | **Blocked** — Nightly #46 on `5384ae2` failed (ignored test + both rehearsal jobs ~2m). `8d73e36` fixes ignored test; M2.4.85 hardens rehearsal jobs. | Confirm Nightly green after next RC auto-dispatch. |

## Recently Completed

- Agent 1: **M2.4.83** — Nightly auto-dispatch (`ref: main` + `checkout_sha`); `5384ae2` CI all 9 jobs green; RC Validation #13 success.
- Agent 1: **M2.4.84** — `three_validator_all_produce_smoke` sortition assertion + height/wait stabilization (`8d73e36`).
- Agent 2: **M2.4.82** — first full green GitHub CI on `e6e8d86` (run 28670552593).
- Agent 3: Windows participant rehearsal PASS (local, `--archive-evidence`).

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.84)

- [x] Windows 30s-slot soak PASS height 38 + RESTART.
- [x] CI queue cleanup preserves current-commit CI.
- [x] First full green GitHub CI (`5384ae2`, run 28673813642).
- [x] RC Validation auto-dispatch Nightly (`5384ae2`, run #13 success).
- [x] Stabilize `three_validator_all_produce_smoke` for nightly (`8d73e36`).

### In Progress (M2.4.85)

- [x] Diagnose Nightly #46 failures on `5384ae2` (ignored sortition assert; rehearsal jobs exit early on cold build).
- [ ] Land `nightly.yml` pre-build + `--no-build` + failure log artifacts + `fetch-depth: 0`.
- [ ] Green CI on `8d73e36` then M2.4.85 push.
- [ ] Green Nightly (ignored suite + both rehearsal jobs).
- [ ] Linux 30s-slot soak evidence.

### Next

- [ ] Archive Linux soak artifact.
- [ ] Operator sign-off on release inventory.

## Agent 3 Detailed Plan

- [x] Windows observer rehearsal PASS + `-ArchiveEvidence`.
- [x] Nightly jobs `--archive-evidence` on Linux.
- [x] RC Validation dispatches Nightly on green CI (verified `5384ae2`).
- [ ] First green **Nightly** (blocked on M2.4.84/85).

## Agent 2 Detailed Plan

- [x] `release-evidence-5384ae2` with CI success URL (`1398cbf`).
- [x] RC audit dry-run decision=go for `e6e8d86`.
- [ ] `release-evidence-8d73e36` after CI green.
- [ ] Operator human sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **PASS** (`5384ae2`); **in flight** (`8d73e36`).
- Nightly after green CI — **auto-dispatch works**; first run failed (#46); fix in `8d73e36` + M2.4.85.
- Linux 30s-slot soak evidence — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Linux Soak Audit requires manual dispatch (`GH_TOKEN` or Actions UI).
- Linux/macOS CI tests take ~70 minutes — do not interrupt with follow-up pushes.
- Unauthenticated GitHub API rate limits — use `gh auth login` or `GH_TOKEN` for CI watch / log fetch.
