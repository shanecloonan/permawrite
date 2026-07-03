# 3agent Coordination

This file coordinates the three active Permawrite agent lanes. Keep using `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and the operator runbooks as the detailed source of truth; this file is the cross-agent handoff board for current work, completed units, and next work.

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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.88** observer boot hardening. | **Ready to push** — fatal observer poll; multi-peer boot dials; GHA 300s catch-up. | Nightly #49 after green CI. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.88** release evidence. | **Pending** — generate after M2.4.88 CI green. | Operator sign-off after Nightly + soak. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.88** full Nightly green. | **In progress** — observer rehearsal harness fixes. | All 3 Nightly jobs green. |

## Recently Completed

- Agent 1: **M2.4.87** pushed (`70b0adb`); Windows `start-all.ps1 -NoBuild` + hub/observer poll progress logs.
- Agent 1: Local Windows participant rehearsal **PASS** (~67s, hub height 5).
- Agent 2: `release-evidence-052e507` + RC audit on `7008d0a`.
- Agent 3: Nightly ignored **PASS** (#48 on `052e507`).

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.87)

- [x] M2.4.87: Windows start-all parity; hub poll progress; pushed `70b0adb`.
- [x] M2.4.86: hub/observer poll 300s; Nightly log dumps; pushed `7008d0a`.
- [x] M2.4.85: `start-all --no-build`; preserve `SLOT_MS`.
- [x] CI #489 green on `052e507` (full matrix).

### M2.4.88 (this push)

- [x] Bash `start-all.sh`: fatal exit when observer RPC missing; poll voter P2P for extra observer boot dials.
- [x] `start-observer.sh`: `config.env` + `EXTRA_P2P_DIALS` multi-peer boot.
- [x] Windows `start-all.ps1`: observer multi-dial + fatal throw on RPC timeout; `--slot-duration-ms` on observer.
- [x] Nightly + rehearsal: GHA `wait-observer-catchup-seconds 300`; longer GHA post-start waits.
- [ ] CI #491 green on `70b0adb` (baseline before M2.4.88).
- [ ] Push M2.4.88 → CI green → RC Validation → Nightly #49.

### Next

- [ ] First full green Nightly (all 3 jobs).
- [ ] `release-evidence-70b0adb` / M2.4.88 after CI green.
- [ ] Linux 30s-slot soak evidence (manual **Linux Soak Audit**).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

- [x] Nightly ignored integration green (#48).
- [ ] First full green **Nightly** — observer rehearsal blocked until M2.4.88 lands.

## Agent 2 Detailed Plan

- [x] `release-evidence-052e507` committed on `7008d0a`.
- [ ] `release-evidence-70b0adb` after CI #491 green.
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI — **in flight** CI #491 on `70b0adb` (M2.4.87 baseline).
- Nightly ignored suite — **PASS** (#48 on `052e507`); rehearsal — **fail** on #47; M2.4.86–M2.4.88 fixes pending Nightly #49.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Wait for CI #491 on `70b0adb` before pushing M2.4.88 (avoid cancel-in-progress).
- Observed local WIP (not in this commit): storage-operator payout keys in `mfn-storage` / `mfn-consensus` — incomplete; do not merge until green.
- Linux Soak Audit manual (~35 min) after first full green Nightly.
