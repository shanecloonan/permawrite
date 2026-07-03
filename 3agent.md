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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.75** CI concurrency + dispatch helpers. | **In progress** — `cancel-in-progress` on CI; `dispatch-rc-workflows`. | Linux Soak Audit workflow dispatch. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.75** release-evidence `7b3ff02`. | **In progress** — evidence + RC audit generating. | Monitor CI after concurrency fix. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.75** local observer rehearsal. | **In progress** — Windows observer smoke running. | Archive PASS evidence; confirm Nightly green. |

## Recently Completed

- Agent 1: **M2.4.74** — `linux-soak-audit.yml` workflow_dispatch (`7b3ff02`).
- Agent 2: **M2.4.74** — `release-evidence-9536efb` + RC audit decision=go.
- Agent 1: **M2.4.70** — Windows 30s-slot soak PASS height 38 + RESTART.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.74)

- [x] Windows + Linux soak success criteria, soak lock, archive evidence.
- [x] Windows 30s-slot soak PASS — `evidence/soak-restart-windows-30s-slot-20260703T132240Z.txt`.
- [x] GitHub Actions **Linux Soak Audit** workflow.

### In Progress (M2.4.75)

- [x] CI `concurrency` + `cancel-in-progress` to clear Actions queue backlog.
- [x] `dispatch-rc-workflows.{ps1,sh}` for Nightly + Linux Soak Audit via `gh`.

### Next

- [ ] Dispatch **Linux Soak Audit** (`dispatch-rc-workflows.ps1 -LinuxSoakAudit` or Actions UI).
- [ ] Commit archived Linux 30s-slot soak evidence from workflow artifact.

## Agent 3 Detailed Plan

- [x] Nightly jobs + `ci-ignored` mirror for both rehearsal smokes.
- [ ] **Running:** Windows observer rehearsal smoke (`-WithObserver -MinHubHeight 5`).
- [ ] First green **Nightly** on post-M2.4.72 commit (manual dispatch).

## Agent 2 Detailed Plan

- [ ] `release-evidence-7b3ff02` + RC audit dry-run.
- [x] CI concurrency fix to unblock green CI on latest `main`.
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

- `gh` not authenticated locally — use Actions UI or `gh auth login` + `dispatch-rc-workflows.ps1 -All`.
- CI queue backlog (M2.4.75 concurrency fix should cancel stale runs on next push).
