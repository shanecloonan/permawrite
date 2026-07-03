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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.79** workflow UTF-8 guard. | **In progress** — fix UTF-16 regression + `validate-workflow-encoding` in CI mirror. | Linux Soak Audit dispatch after CI green. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.79** CI monitor. | **In progress** — `2342b75` CI running; cleanup failed (UTF-16). | Release-evidence for first green CI commit. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.78** Nightly auto-dispatch. | **Waiting** — RC validation fires after green CI. | Confirm Nightly green + archived Linux evidence. |

## Recently Completed

- Agent 1: **M2.4.78** — `rc-validation-after-ci.yml`, bash `--archive-evidence`, Nightly wiring (`794d98c`).
- Agent 1: **M2.4.77** — CI queue cleanup UTF-8 fix (`d6298d4`).
- Agent 1: **M2.4.70** — Windows 30s-slot soak PASS height 38 + RESTART.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.78)

- [x] Windows 30s-slot soak PASS + soak lock + archive evidence.
- [x] CI queue cleanup + RC validation auto-dispatch Nightly.
- [x] Linux Soak Audit workflow.

### In Progress (M2.4.79)

- [x] Rewrite `ci-queue-cleanup.yml` as UTF-8 (regression in `2342b75` re-introduced UTF-16).
- [x] `.gitattributes` + `validate-workflow-encoding.{ps1,sh}` in local CI mirror.
- [ ] Green GitHub CI on latest push.

### Next

- [ ] Manual **Linux Soak Audit** dispatch once CI green.
- [ ] Commit archived Linux 30s-slot soak evidence from workflow artifact.

## Agent 3 Detailed Plan

- [x] Windows observer rehearsal PASS + `-ArchiveEvidence`.
- [x] Nightly jobs use `--archive-evidence` on Linux.
- [ ] First green **Nightly** via RC validation on green CI commit.

## Agent 2 Detailed Plan

- [x] `release-evidence-ad18d94` + RC audit decision=go.
- [ ] Regenerate release-evidence for latest green CI commit.
- [ ] Operator human sign-off on release inventory.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI.
- Local CI mirror passed (includes workflow UTF-8 check).
- Nightly + ci-ignored smoke coverage for release candidates.
- `release-evidence.md` / `.json` for exact commit.
- RC audit dry-run packet archived (`decision=go`).
- Linux 30s-slot soak evidence (Windows done; Linux workflow pending).
- Support bundle + archive validation + human sign-off.

## Cross-Agent Blockers

- `2342b75` accidentally re-committed `ci-queue-cleanup.yml` as UTF-16 — **M2.4.79** fixes + prevents recurrence.
- Linux 30s-slot soak requires manual workflow dispatch (90min job).
