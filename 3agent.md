# 3agent Coordination

This file coordinates the three active Permawrite agent lanes. Keep using `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and the operator runbooks as the detailed source of truth; this file is the cross-agent handoff board for current work, completed units, and next handoff.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

## Update Protocol

- Update this file at the start or end of every coherent agent unit.
- Record the exact lane owner, current unit, status, blockers, and next handoff.
- Do not claim another agent's uncommitted work; mention it as "observed local work" until it lands on `main`.
- Continue updating `docs/TESTNET_CHECKLIST.md` for durable release-readiness tasks.
- Commit and push completed units to `main` after the required local CI mirror passes.
- **Do not push while CI is in progress** — concurrency `cancel-in-progress` aborts the matrix (~70 min on Linux/macOS).

## Current Board

| Agent | Lane | Current Unit | Status | Next Handoff |
| --- | --- | --- | --- | --- |
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.89** CI re-run after ubuntu flake. | **In progress** — CI #492 ubuntu-only fail on scripts-only `297ec27`. | Green CI #493 → Nightly #49. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.89** release evidence. | **Pending** — `release-evidence-297ec27` after green CI. | Operator sign-off after Nightly + soak. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.88** full Nightly green. | **Blocked** — RC Validation skipped until CI green. | All 3 Nightly jobs green. |

## Recently Completed

- Agent 1: **M2.4.88** pushed (`297ec27`) — observer fatal poll, multi-peer boot dials, GHA 300s catch-up.
- Agent 1: **M2.4.87** (`70b0adb`); Windows `start-all.ps1 -NoBuild` + hub/observer poll progress.
- Agent 2: `release-evidence-052e507` + RC audit on `7008d0a`.
- Agent 3: Nightly ignored **PASS** (#48 on `052e507`).

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.88)

- [x] M2.4.88: observer boot hardening; pushed `297ec27`.
- [x] M2.4.87: Windows start-all parity; pushed `70b0adb`.
- [x] M2.4.86: hub/observer poll 300s; Nightly log dumps; `7008d0a`.
- [x] CI #489 green on `052e507` (full matrix).

### In Progress (M2.4.89)

- [x] Diagnose CI #492 (run `28687976097`): **ubuntu** `cargo test` fail; **macos + windows success**; rustfmt/clippy/wasm/audit/scripts **pass**; **zero Rust diff** `052e507..297ec27` → isolated runner flake (same pattern as CI #490 on `7008d0a`).
- [ ] Local CI mirror PASS on `297ec27`.
- [ ] Board truth commit → push → CI #493 green.

### Next

- [ ] RC Validation → Nightly #49 on green `297ec27`.
- [ ] First full green Nightly (all 3 jobs).
- [ ] `release-evidence-297ec27` after CI green.
- [ ] Linux 30s-slot soak evidence (manual **Linux Soak Audit**).

## Agent 3 Detailed Plan

- [x] Nightly ignored integration green (#48).
- [ ] First full green **Nightly** — blocked on green CI for RC auto-dispatch.

## Agent 2 Detailed Plan

- [x] `release-evidence-052e507` committed on `7008d0a`.
- [ ] `release-evidence-297ec27` after CI #493 green.
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **FAIL** CI #492 on `297ec27` (ubuntu test only; macos/windows/scripts green).
- Nightly ignored suite — **PASS** (#48 on `052e507`); full Nightly — **fail** #48 rehearsal; M2.4.88 fixes pending Nightly #49.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- CI red on `297ec27` blocks RC Validation → Nightly #49.
- Observed local WIP (not on `main`): storage-operator payout keys in Rust — incomplete; do not merge until green.
- Linux Soak Audit manual (~35 min) after first full green Nightly.
