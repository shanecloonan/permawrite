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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.76** CI queue cleanup + soak workflow concurrency. | **Done locally** — `ci-queue-cleanup.yml`, dispatch REST fallback. | Dispatch Linux Soak Audit; archive Linux evidence. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.76** release-evidence `ad18d94`. | **Done locally** — evidence + RC audit archived. | Monitor CI green after queue cleanup. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.76** observer rehearsal + `-ArchiveEvidence`. | **Done** — PASS `participant-rehearsal-observer-windows-20260703T140456Z.txt`. | Green Linux Nightly (both jobs). |

## Recently Completed

- Agent 1: **M2.4.75** — CI `cancel-in-progress`; `dispatch-rc-workflows` (`ad18d94`).
- Agent 3: **M2.4.76** — Windows observer rehearsal PASS re-archived; `-ArchiveEvidence` on smoke.ps1.
- Agent 2: **M2.4.76** — `release-evidence-ad18d94` + RC audit decision=go.
- Agent 1: **M2.4.70** — Windows 30s-slot soak PASS height 38 + RESTART.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.76)

- [x] Windows + Linux soak success criteria, soak lock, archive evidence.
- [x] Windows 30s-slot soak PASS — `evidence/soak-restart-windows-30s-slot-20260703T132240Z.txt`.
- [x] GitHub Actions **Linux Soak Audit** + **CI Queue Cleanup** workflows.
- [x] `dispatch-rc-workflows` with gh + `GH_TOKEN` REST fallback.

### Next

- [ ] `dispatch-rc-workflows.ps1 -LinuxSoakAudit` (or Actions UI) — ~35 min Linux soak.
- [ ] Commit Linux 30s-slot soak evidence from workflow artifact.

## Agent 3 Detailed Plan

- [x] Nightly jobs + `ci-ignored` mirror for both rehearsal smokes.
- [x] Windows observer rehearsal PASS (`participant-rehearsal-observer-windows-20260703T140456Z.txt`).
- [x] `participant-rehearsal-smoke.ps1 -ArchiveEvidence` switch.
- [ ] First green **Nightly** on post-M2.4.72 commit (`dispatch-rc-workflows.ps1 -Nightly`).

## Agent 2 Detailed Plan

- [x] `release-evidence-ad18d94` + RC audit dry-run.
- [x] CI queue cleanup workflow to unblock Actions backlog.
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

- Dispatch workflows requires `gh auth login` or `GH_TOKEN` / `GITHUB_TOKEN`.
- Linux Nightly not yet run on post-M2.4.72 commit (manual dispatch required).
