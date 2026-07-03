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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.82** preserve current-commit CI in queue cleanup. | **In progress** — fix race that cancelled every CI run. | Wait for full green CI; then Linux Soak Audit. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.82** CI green gate. | **Waiting** — prior runs cancelled by follow-up pushes. | Release-evidence for first fully green commit. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.78** Nightly auto-dispatch. | **Waiting** — RC validation only fires on CI success. | Confirm Nightly green + Linux soak evidence. |

## Recently Completed

- Agent 1: **M2.4.81** — CI `workflow_dispatch`; wasm-pack repository metadata fix; release-evidence-2497668.
- Agent 1: **M2.4.80** — validate-workflow-encoding python3 fix.
- Agent 2: **M2.4.81** — RC audit dry-run decision=go for 2497668.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.81)

- [x] Windows 30s-slot soak PASS height 38 + RESTART.
- [x] CI queue cleanup + RC validation + workflow UTF-8 guard.
- [x] Linux Soak Audit workflow.
- [x] M2.4.80 validate script fix; public-devnet scripts green on GitHub.
- [x] M2.4.81 workflow_dispatch + wasm-pack fix.

### In Progress (M2.4.82)

- [x] CI Queue Cleanup preserves CI runs for `context.sha` (stop cancelling the commit under test).
- [x] RC Validation After CI also accepts `workflow_dispatch` CI success.
- [ ] Green **full** GitHub CI on M2.4.82 commit (no follow-up pushes until done).
- [ ] Linux 30s-slot soak evidence (manual **Linux Soak Audit** dispatch).

### Next

- [ ] Archive Linux soak artifact once workflow completes.
- [ ] Operator sign-off on release inventory.

## Agent 3 Detailed Plan

- [x] Windows observer rehearsal PASS + `-ArchiveEvidence`.
- [x] Nightly jobs `--archive-evidence` on Linux.
- [ ] First green **Nightly** via RC validation when full CI passes.

## Agent 2 Detailed Plan

- [x] `release-evidence-2497668` + RC audit decision=go.
- [ ] Verify GitHub CI green on exact M2.4.82 commit.
- [ ] Regenerate release-evidence for that green commit.
- [ ] Operator human sign-off.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **blocked by cancel-in-progress from rapid pushes**; M2.4.82 holds the line.
- Local CI mirror — validate scripts PASS; full mirror not required for workflow-only change.
- Nightly after green CI — **pending** RC validation trigger.
- Linux 30s-slot soak evidence — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Rapid follow-up pushes cancelled CI on `2497668`, `e14df80`, `02a660e` before the test matrix finished.
- M2.4.82 must land and then **no further pushes** until CI is green.
- Linux Soak Audit + Nightly require GitHub Actions (~35–90 min each); need `GH_TOKEN` or Actions UI for manual dispatch.