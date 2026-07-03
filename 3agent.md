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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.74** Linux soak audit workflow. | **Done locally** — `linux-soak-audit.yml` workflow_dispatch. | Trigger workflow; archive Linux 30s evidence artifact. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.74** release-evidence + RC audit for `9536efb`. | **Done locally** — evidence + decision=go archived. | Monitor CI queue; operator sign-off. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.74** nightly dispatch guidance. | **Done locally** — OPERATORS docs for manual Nightly run. | Confirm green Nightly (both rehearsal jobs) on `9536efb+`. |

## Recently Completed

- Agent 1: **M2.4.73** — Linux `soak.sh` parity + bash soak lock (`9536efb`).
- Agent 2: **M2.4.73** — RC audit dry-run decision=go archived.
- Agent 1: **M2.4.70** — Windows 30s-slot soak PASS height 38 + RESTART evidence.
- Agent 3: **M2.4.68** — observer-enabled rehearsal PASS hub≥5.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.74)

- [x] Windows + Linux soak success criteria, archive evidence, soak lock (ps1 + bash).
- [x] Windows 30s-slot soak PASS — `evidence/soak-restart-windows-30s-slot-20260703T132240Z.txt`.
- [x] GitHub Actions **Linux Soak Audit** workflow (`linux-soak-audit.yml`, workflow_dispatch, artifact upload).

### Next

- [ ] Run **Linux Soak Audit** on GitHub Actions; commit archived Linux 30s-slot evidence.
- [ ] Monitor CI green for `9536efb` / M2.4.74 push.

## Agent 3 Detailed Plan

- [x] Nightly jobs: `participant-rehearsal-smoke` + `participant-rehearsal-smoke-observer`.
- [x] `ci-ignored` mirrors both jobs locally.
- [x] OPERATORS guidance to manually dispatch **Nightly** before RC sign-off.
- [ ] First green Nightly on commit **after M2.4.72** (observer job included).

## Agent 2 Detailed Plan

- [x] `release-evidence-9536efb.json` / `.md`.
- [x] `rc-audit-dry-run-9536efb-*.json` (decision=go).
- [ ] GitHub CI green on latest push (runs were queued — monitor Actions).
- [ ] Operator human sign-off on release inventory.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI.
- Local CI mirror passed.
- Nightly + ci-ignored smoke coverage for release candidates.
- `release-evidence.md` / `.json` for exact commit.
- RC audit dry-run packet archived (`decision=go`).
- Linux 30s-slot soak evidence (Windows done; Linux via workflow artifact pending).
- Support bundle + archive validation + human sign-off.

## Cross-Agent Blockers

- GitHub Actions CI queue backlog (multiple `main` pushes queued/in_progress).
- Last scheduled Nightly (`cc7cb19`) predates M2.4.72 observer job — manual **Nightly** dispatch required to validate both rehearsal jobs.
- Local `gh` not authenticated; use Actions UI for workflow dispatch and CI monitoring.
