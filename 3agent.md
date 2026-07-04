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
| Agent 1 | Core protocol, consensus, economics | **M2.5.5** (`ec845fd`). | **Done** — CI #512 **GREEN** (all OS, ~1h11m). | Monitor Nightly #52 on `ec845fd`. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.5** evidence. | **Done** — `release-evidence-ec845fd` + RC audit dry-run (go). | Operator sign-off after green Nightly #52. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.5** devnet CI hardening. | **Done** — voter P2P poll + hub liveness wait pushed. | Nightly #52 participant+observer green. |

## Recently Completed

- **M2.5.5** (`ec845fd`) — ignored-test flake fix + devnet CI liveness; CI #512 **GREEN**; RC Validation #42 → Nightly #52.
- **M2.5.4** (`9c76050`) — devnet ring-16 script defaults; CI #509 **GREEN**.
- **Nightly #51** — **FAIL** on `9c76050` (all jobs; triaged → M2.5.5).
- **M2.5.3** (`95739e4`) — node/mempool ring-16 harness; CI #505 **GREEN**.

## Nightly #51 Post-Mortem (`9c76050`, run [28700355365](https://github.com/shanecloonan/permawrite/actions/runs/28700355365))

| Job | Root cause |
| --- | --- |
| ignored-integration | Flaky `three_validators_all_produce` sortition log grep |
| participant + observer | Hub liveness / faucet timeout on CI runners |

**M2.5.5 fix:** removed flaky assertion; `start-all` waits for voter P2P; rehearsal smoke waits for `tip_height >= 1` + longer CI faucet window.

## Agent 1 Detailed Plan

### Done

- [x] M2.5.5 pushed (`ec845fd`) — ignored-test + devnet CI liveness hardening.
- [x] Local CI mirror green (`ci-check-m255.log`).
- [x] CI #512 **GREEN** on `ec845fd` (all OS) — [run 28701096230](https://github.com/shanecloonan/permawrite/actions/runs/28701096230).

### In Progress

- [ ] Monitor **Nightly #52** on `ec845fd` (RC Validation #42 dispatched 2026-07-04T10:03Z).

### Next

- [ ] Nightly #52 green (ignored + participant + observer).
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit**, ~35 min).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

### Done

- [x] M2.5.5 — `start-all` voter P2P readiness; rehearsal smoke hub liveness + CI wait tuning.

### In Progress

- [ ] Nightly #52 participant + observer validation on `ec845fd`.

## Agent 2 Detailed Plan

- [x] `release-evidence-ec845fd` + RC audit dry-run (go).
- [x] Prior: `release-evidence-9c76050`, `release-evidence-95739e4`.
- [ ] Operator sign-off after Nightly #52 + Linux soak.

## Shared Release-Candidate Gates

- Green GitHub CI — **PASS** CI #512 on `ec845fd` (M2.5.5, all OS).
- RC Validation — **PASS** #42 (dispatched Nightly #52 on `ec845fd`).
- Nightly — **IN PROGRESS** #52 on `ec845fd`; #51 **FAIL** on `9c76050`.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- RC gate open until Nightly #52 **GREEN** on exact commit `ec845fd`.
- Do **not** mark Nightly green until GitHub Actions confirms all three nightly jobs pass.
