# 3agent Coordination

This file coordinates the three active Permawrite agent lanes. Keep using `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and the operator runbooks as the detailed source of truth; this file is the cross-agent handoff board for current work, completed units, and next work.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

## Update Protocol

- Update this file at the start or end of every coherent agent unit.
- Record the exact lane owner, current unit, status, blockers, and next handoff.
- Do not claim another agent's uncommitted work; mention it as "observed local work" until it lands on `main`.
- Continue updating `docs/TESTNET_CHECKLIST.md` for durable release-readiness tasks.
- Commit and push completed units to `main` after the required local CI mirror passes.
- **Do not push docs-only follow-ups while CI is in progress** — concurrency `cancel-in-progress` aborts the matrix before tests finish (Linux/macOS release tests often take 45–75 minutes).

## Current Board

| Agent | Lane | Current Unit | Status | Next Handoff |
| --- | --- | --- | --- | --- |
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.84** Nightly ignored-test fix. | **In progress** — fix flaky sortition assertion in all-produce smoke. | Re-dispatch Nightly after green CI. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.83** release evidence. | **Done** — `e6e8d86` + `5384ae2` evidence archived. | Operator sign-off after Nightly + Linux soak. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.84** Nightly green. | **Blocked** — Nightly #46 failed (ignored produce smoke). | Confirm Nightly after M2.4.84. |

## Recently Completed

- Agent 1: **M2.4.83** — Nightly dispatch fix; CI **success** + RC Validation **success** on `5384ae2`.
- Agent 2: **M2.4.83** — `release-evidence-5384ae2` archived after green dispatch commit.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.82)

- [x] Windows 30s-slot soak PASS height 38 + RESTART.
- [x] CI queue cleanup preserves current-commit CI.
- [x] Linux Soak Audit workflow.
- [x] First full green GitHub CI (`e6e8d86`, run 28670552593).

### In Progress (M2.4.84)

- [x] Diagnose Nightly #46: `three_validators_all_produce_converge_on_shared_tip` sortition assertion.
- [x] Wait to height 3; accept `slot_skip` or `slot_advance` as sortition evidence.
- [ ] Green CI on M2.4.84 push (hold line until matrix finishes).
- [ ] Green Nightly via RC Validation.
- [ ] Linux 30s-slot soak evidence.

### Next

- [ ] Archive Linux soak artifact.
- [ ] Operator sign-off on release inventory.

## Agent 3 Detailed Plan

- [x] Windows observer rehearsal PASS + `-ArchiveEvidence`.
- [x] Nightly jobs `--archive-evidence` on Linux.
- [ ] First green **Nightly** via fixed RC validation.

## Agent 2 Detailed Plan

- [x] `release-evidence-e6e8d86` with CI success URL.
- [x] RC audit dry-run decision=go for `e6e8d86`.
- [ ] Operator human sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **PASS** (`5384ae2`, run 28673813642).
- Nightly after green CI — **Nightly #46 failed** (ignored produce smoke); M2.4.84 fix in flight.
- Linux 30s-slot soak evidence — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Linux Soak Audit requires manual dispatch (`GH_TOKEN` or Actions UI).
- Linux/macOS CI tests take ~70 minutes — do not interrupt with follow-up pushes.