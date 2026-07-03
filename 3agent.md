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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.76** CI queue cleanup + flaky P2P upload retry. | **In progress** — `ci-queue-cleanup.yml`; chunk upload transport retry. | Monitor Linux Soak Audit after dispatch. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.76** release-evidence `ad18d94`. | **In progress** — RC evidence + CI unblock. | Archive validation after CI green. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.76** observer rehearsal evidence UTF-8 fix. | **Done** — PASS archived + `-ArchiveEvidence` on smoke.ps1. | Green Nightly dispatch (both jobs). |

## Recently Completed

- Agent 1: **M2.4.75** — CI concurrency + `dispatch-rc-workflows` helpers (`ad18d94`).
- Agent 1: **M2.4.70** — Windows 30s-slot soak PASS height 38 + RESTART.
- Agent 3: **M2.4.68** — observer-enabled rehearsal PASS hub≥5.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.75)

- [x] Windows 30s-slot soak PASS + soak lock + archive evidence.
- [x] Linux Soak Audit workflow + CI concurrency cancel-in-progress.

### In Progress (M2.4.76)

- [x] `ci-queue-cleanup.yml` cancels stale CI runs on main (unblocks Actions backlog).
- [x] `chunk_p2p_auto_fanout_smoke` wallet upload transport retry (Windows RPC flake).
- [ ] Linux 30s-slot soak evidence from **Linux Soak Audit** workflow artifact.

### Next

- [ ] Dispatch `dispatch-rc-workflows.ps1 -All` (or Actions UI: CI Queue Cleanup → Nightly → Linux Soak Audit).
- [ ] Commit archived Linux soak evidence once workflow completes.

## Agent 3 Detailed Plan

- [x] Windows observer rehearsal PASS — `evidence/participant-rehearsal-observer-windows-20260703T140456Z.txt`.
- [x] `-ArchiveEvidence` on `participant-rehearsal-smoke.ps1` (UTF-8 no BOM via `ports-env-lib`).
- [ ] First green **Nightly** on post-M2.4.72 commit (manual dispatch).

## Agent 2 Detailed Plan

- [ ] `release-evidence-ad18d94` + RC audit dry-run for latest RC commit.
- [x] CI queue cleanup workflow to unblock green CI.
- [ ] Operator human sign-off on release inventory.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI.
- Local CI mirror passed.
- Nightly + ci-ignored smoke coverage for release candidates.
- `release-evidence.md` / `.json` for exact commit.
- RC audit dry-run packet archived (`decision=go`).
- Linux 30s-slot soak evidence (Windows done; Linux workflow pending).
- Support bundle + archive validation + human sign-off.

## Cross-Agent Blockers

- GitHub Actions CI backlog (5+ stale `in_progress` runs) — **M2.4.76** `ci-queue-cleanup.yml` runs on push.
- `gh` not installed locally — use Actions UI or set `GH_TOKEN`/`GITHUB_TOKEN` for REST dispatch via `dispatch-rc-workflows.ps1`.
