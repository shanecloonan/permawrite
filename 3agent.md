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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.80** validate script fix. | **Done locally** — UTF-8 `.sh`/`.ps1` rewrites + python3 byte check; ci-check PASS. | Linux Soak Audit after CI green. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.80** CI monitor + release evidence. | **In progress** — push + watch GitHub CI. | Release-evidence for first green CI commit. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.78** Nightly auto-dispatch. | **Waiting** — RC validation after green CI. | Confirm Nightly green + Linux evidence. |

## Recently Completed

- Agent 1: **M2.4.80** — rewrite `validate-workflow-encoding.{sh,ps1}` as UTF-8; python3 BOM/null-byte check (fixes GNU grep false positive + UTF-16 corruption on Windows).
- Agent 1: **M2.4.79** — UTF-8 workflow guard; CI queue cleanup **success** (`b581e78`).
- Agent 2: **M2.4.79** — `release-evidence-b581e78` + RC audit decision=go.
- Agent 1: **M2.4.78** — RC validation auto-dispatch Nightly.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.79)

- [x] Windows 30s-slot soak PASS height 38 + RESTART.
- [x] CI queue cleanup + RC validation + workflow UTF-8 guard.
- [x] Linux Soak Audit workflow.

### In Progress (M2.4.80)

- [x] Fix `validate-workflow-encoding.sh` — UTF-8 rewrite + python3 byte check (replaces broken UTF-16 file and grep false positive).
- [x] Local CI mirror PASS (`scripts/ci-check.ps1`).
- [ ] Green GitHub CI on latest push.
- [ ] Linux 30s-slot soak evidence (manual **Linux Soak Audit** dispatch).

### Next

- [ ] Archive Linux soak artifact once workflow completes.
- [ ] Operator sign-off on release inventory.

## Agent 3 Detailed Plan

- [x] Windows observer rehearsal PASS + `-ArchiveEvidence`.
- [x] Nightly jobs `--archive-evidence` on Linux.
- [ ] First green **Nightly** via RC validation when CI passes.

## Agent 2 Detailed Plan

- [x] `release-evidence-b581e78` + RC audit decision=go.
- [ ] Verify GitHub CI green on M2.4.80 commit (after push).
- [ ] Operator human sign-off.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **in flight** (M2.4.80 validate fix pushed).
- Local CI mirror passed — **yes** (M2.4.79).
- Nightly after green CI — **pending** RC validation trigger.
- Linux 30s-slot soak evidence — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- None critical; M2.4.80 validate fix landed locally. Await first green CI, then auto Nightly.
