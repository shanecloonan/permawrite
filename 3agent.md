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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.81** CI re-run + Linux soak. | **In progress** — `workflow_dispatch` on CI; push to re-trigger green run. | Dispatch **Linux Soak Audit** after CI green. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.81** release evidence. | **In progress** — `release-evidence-2497668` + RC audit decision=go. | Confirm GitHub CI green on `2497668`/`M2.4.81` push. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.78** Nightly auto-dispatch. | **Waiting** — RC validation after green CI. | Confirm Nightly green + archived Linux evidence. |

## Recently Completed

- Agent 1: **M2.4.80** — validate-workflow-encoding python3 fix; public-devnet scripts **success** on GitHub before CI cancel (`2497668`).
- Agent 2: **M2.4.80** — RC audit dry-run decision=go for validate fix commit.
- Agent 1: **M2.4.79** — UTF-8 workflow guard; CI queue cleanup success.
- Agent 2: **M2.4.79** — `release-evidence-b581e78` + RC audit decision=go.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.80)

- [x] Windows 30s-slot soak PASS height 38 + RESTART.
- [x] CI queue cleanup + RC validation + workflow UTF-8 guard.
- [x] Linux Soak Audit workflow.
- [x] M2.4.80 validate script fix (`2497668`) — public-devnet scripts green on GitHub.

### In Progress (M2.4.81)

- [x] Add `workflow_dispatch` to CI for manual re-run without empty commits.
- [ ] Green **full** GitHub CI (2497668 run cancelled during tests; re-trigger via push).
- [ ] Linux 30s-slot soak evidence (manual **Linux Soak Audit** dispatch).

### Next

- [ ] Archive Linux soak artifact once workflow completes.
- [ ] Operator sign-off on release inventory.

## Agent 3 Detailed Plan

- [x] Windows observer rehearsal PASS + `-ArchiveEvidence`.
- [x] Nightly jobs `--archive-evidence` on Linux.
- [ ] First green **Nightly** via RC validation when full CI passes.

## Agent 2 Detailed Plan

- [x] `release-evidence-2497668` + `rc-audit-dry-run-2497668-20260703T153350Z.json` decision=go.
- [ ] Verify GitHub CI green on exact RC commit after M2.4.81 push.
- [ ] Operator human sign-off.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **2497668 validate fix proven**; full matrix re-run pending.
- Local CI mirror — **yes** (`scripts/ci-check.ps1` PASS before M2.4.81 push).
- Nightly after green CI — **pending** RC validation trigger.
- Linux 30s-slot soak evidence — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- GitHub API rate limit (unauthenticated) — use Actions UI or `GH_TOKEN` for dispatch/monitoring.
- Linux Soak Audit + Nightly require GitHub Actions (~35–90 min each).
