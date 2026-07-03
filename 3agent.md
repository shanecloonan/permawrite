# 3agent Coordination

This file coordinates the three active Permawrite agent lanes. Keep using `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and the operator runbooks as the detailed source of truth; this file is the cross-agent handoff board for current work, completed units, and next work.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

## Update Protocol

- Update this file at the start or end of every coherent agent unit.
- Record the exact lane owner, current unit, status, blockers, and next handoff.
- Do not claim another agent's uncommitted work; mention it as "observed local work" until it lands on `main`.
- Continue updating `docs/TESTNET_CHECKLIST.md` for durable release-readiness tasks.
- Commit and push completed units to `main` after the required local CI mirror passes.
- **Do not push docs-only follow-ups while CI is in progress** — concurrency `cancel-in-progress` aborts the matrix before tests finish.

## Current Board

| Agent | Lane | Current Unit | Status | Next Handoff |
| --- | --- | --- | --- | --- |
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.83** RC validation nightly dispatch ref. | **In progress** — fix `ref: sha` → branch name. | Linux Soak Audit after Nightly green. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.82** release evidence. | **Done** — `release-evidence-e6e8d86` + RC audit decision=go; CI **success** run 28670552593. | Confirm Nightly dispatch after M2.4.83. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.83** Nightly dispatch. | **Blocked** — RC Validation #12 failed (`No ref found for sha`). | Confirm Nightly green once dispatch fixed. |

## Recently Completed

- Agent 1: **M2.4.82** — CI Queue Cleanup preserves `context.sha`; first **full green CI** on `e6e8d86` (run 28670552593).
- Agent 2: **M2.4.82** — `release-evidence-e6e8d86` + RC audit dry-run decision=go.
- Agent 1: **M2.4.81** — CI `workflow_dispatch`; wasm-pack repository metadata fix; release-evidence-2497668.
- Agent 1: **M2.4.80** — validate-workflow-encoding python3 fix.
- Agent 2: **M2.4.81** — RC audit dry-run decision=go for 2497668.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.82)

- [x] Windows 30s-slot soak PASS height 38 + RESTART.
- [x] CI queue cleanup + RC validation + workflow UTF-8 guard.
- [x] Linux Soak Audit workflow.
- [x] M2.4.80 validate script fix; public-devnet scripts green on GitHub.
- [x] M2.4.81 workflow_dispatch + wasm-pack fix.
- [x] M2.4.82 queue cleanup preserves current-commit CI; **full green CI** on `e6e8d86`.

### In Progress (M2.4.83)

- [x] Fix RC Validation nightly dispatch — use branch ref not commit SHA.
- [ ] Green GitHub CI on M2.4.83 push (workflow-only; hold line after push).
- [ ] Nightly auto-dispatch via fixed RC Validation.
- [ ] Linux 30s-slot soak evidence (manual **Linux Soak Audit** dispatch).

### Next

- [ ] Archive Linux soak artifact once workflow completes.
- [ ] Operator sign-off on release inventory.

## Agent 3 Detailed Plan

- [x] Windows observer rehearsal PASS + `-ArchiveEvidence`.
- [x] Nightly jobs `--archive-evidence` on Linux.
- [ ] First green **Nightly** via RC validation when full CI passes.

## Agent 2 Detailed Plan

- [x] `release-evidence-e6e8d86` + RC audit decision=go (CI success run 28670552593).
- [ ] Verify Nightly dispatch after M2.4.83 RC validation fix.
- [ ] Operator human sign-off.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **yes** (`e6e8d86`, run 28670552593).
- Local CI mirror — validate scripts PASS; full mirror before protocol changes.
- Nightly after green CI — **RC Validation #12 failed** (sha ref); M2.4.83 fix in flight.
- Linux 30s-slot soak evidence — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- RC Validation nightly dispatch used commit SHA as `ref` — GitHub requires branch/tag (**M2.4.83** fix).
- After M2.4.83 lands: optionally run **RC Validation After CI** via `workflow_dispatch` with `ci_head_sha=e6e8d86` to fire Nightly without waiting for another full CI matrix.