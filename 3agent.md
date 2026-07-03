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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.83** Nightly + Linux soak. | **Watching** — CI **success** on `5384ae2`; RC Validation **success**; Nightly in progress. | Linux Soak Audit after Nightly green. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.83** release evidence `5384ae2`. | **In progress** — archiving evidence + RC audit for green dispatch commit. | Operator sign-off after Nightly + Linux soak. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.83** Nightly validation. | **In progress** — Nightly dispatched with `checkout_sha=5384ae2`. | Confirm both rehearsal jobs green. |

## Recently Completed

- Agent 1: **M2.4.83** — Nightly dispatch fix (`ref: main` + `checkout_sha`); CI **success** + RC Validation **success** on `5384ae2`.
- Agent 2: **M2.4.82** — first **full green GitHub CI** on `e6e8d86` (all 9 jobs, including Linux/macOS tests ~70 min).
- Agent 2: **M2.4.82** — `release-evidence-e6e8d86` + RC audit decision=go.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.82)

- [x] Windows 30s-slot soak PASS height 38 + RESTART.
- [x] CI queue cleanup preserves current-commit CI.
- [x] Linux Soak Audit workflow.
- [x] First full green GitHub CI (`e6e8d86`, run 28670552593).

### In Progress (M2.4.83)

- [x] Diagnose RC Validation failure: `createWorkflowDispatch` rejects commit SHA as `ref`.
- [x] Dispatch Nightly with `ref: main` + `inputs.checkout_sha`.
- [x] Green CI on `5384ae2` (M2.4.83 dispatch fix).
- [x] RC Validation auto-dispatch **success** (Nightly running with `checkout_sha=5384ae2`).
- [ ] Green Nightly (ignored suite + both rehearsal jobs).
- [ ] Linux 30s-slot soak evidence.

### Next

- [ ] Archive Linux soak artifact.
- [ ] Operator sign-off on release inventory.

## Agent 3 Detailed Plan

- [x] Windows observer rehearsal PASS + `-ArchiveEvidence`.
- [x] Nightly jobs `--archive-evidence` on Linux.
- [ ] First green **Nightly** via fixed RC validation.

## Agent 2 Detailed Plan

- [x] `release-evidence-e6e8d86` with CI success URL.
- [x] RC audit dry-run decision=go for `e6e8d86`.
- [ ] Operator human sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **PASS** (`5384ae2`, run 28673813642).
- Nightly after green CI — **in progress** (auto-dispatched via RC Validation M2.4.83).
- Linux 30s-slot soak evidence — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Linux Soak Audit requires manual dispatch (`GH_TOKEN` or Actions UI).
- Linux/macOS CI tests take ~70 minutes — do not interrupt with follow-up pushes.