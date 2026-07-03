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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.71** soak success criteria + graceful deadline exit. | **In progress** — `-MinFinalHeight`, convergence retries, archive on finish. | Monitor nightly observer smoke (Agent 3). |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.72** release-evidence for `ebe1e48`. | **Done locally** — JSON + MD in `evidence/`. | Archive validation packet after CI green. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.72** nightly observer rehearsal job. | **Done locally** — `participant-rehearsal-smoke-observer` in nightly.yml. | Confirm first Linux nightly green (both jobs). |

## Recently Completed

- Agent 1: **M2.4.70** — soak lock + ports snapshot; 30s-slot 35min PASS height 38 + RESTART evidence archived.
- Agent 3: **M2.4.68** — observer-enabled rehearsal PASS hub≥5 + evidence archived.
- Agent 3: **M2.4.67** — nightly + ci-ignored participant-rehearsal-smoke promotion.
- Agent 1: **M2.4.66** — Windows soak SUMMARY PASS + `soak: RESTART` (height 28, 10s slots).

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.70)

- [x] Mesh stability, soak RESTART, devnet-ports mutex, observer rehearsal past height 5.
- [x] Soak `-ArchiveEvidence` switch + OPERATORS 30s-slot command documented.
- [x] Soak lock (`.soak-active.lock`) blocks `start-all`/`stop-all` during long soaks.
- [x] In-memory ports snapshot restores `devnet-ports.env` if deleted while mesh PIDs stay alive.
- [x] Windows 30s-slot soak PASS (`SLOT_MS=30000`, 35 min, height 38, RESTART) — `evidence/soak-restart-windows-30s-slot-20260703T132240Z.txt`.

### In Progress (M2.4.71)

- [x] `-MinFinalHeight` / `-MinSuccessfulIterations` success criteria for production-slot audits.
- [x] Graceful soak exit when deadline approaches but criteria already met (convergence_timeout retry + criteria break).
- [x] `-ArchiveEvidence` writes transcript on PASS or FAIL.

### Next

- [ ] Linux 30s-slot soak parity in `soak.sh` (deadline budget + success criteria).
- [ ] Release archive dry-run with M2.4.70 evidence bundle (Agent 2).

## Agent 3 Detailed Plan

- [x] Observer-enabled rehearsal PASS (M2.4.68).
- [x] Nightly workflow job `participant-rehearsal-smoke-observer` with `--with-observer --min-hub-height 5`.
- [ ] Confirm first green Linux nightly for both rehearsal jobs.

## Agent 2 Detailed Plan

- [x] Generate `release-evidence` JSON/MD for commit `ebe1e48` (`evidence/release-evidence-ebe1e48.*`).
- [ ] Monitor GitHub CI for current push (run 28663434467 was queued).
- [ ] Run `release-audit-packet` dry-run once CI green.
- [ ] Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md`.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI.
- Local CI mirror passed.
- Nightly + ci-ignored smoke coverage for release candidates.
- `release-evidence.md` / `.json` for exact commit.
- Support bundle + archive validation + human sign-off.
