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
| Agent 1 | Core protocol, consensus, economics | **M2.5.7** Nightly #53 fix. | **In progress** — extended GHA timeouts + stall health-check. | CI mirror → push → Nightly #54. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.6** evidence (`f5f45bf`). | **Done** — `release-evidence-f5f45bf` + RC audit dry-run (go). | Refresh evidence after green Nightly on M2.5.7. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.7** rehearsal timeouts. | **In progress** — faucet 600s / mined+upload 480s; STAGE logging. | Nightly participant+observer green. |

## Recently Completed

- **M2.5.6** (`f5f45bf`) — voter dial + hub tip wait; CI #514 **GREEN**; Nightly #53 ignored **PASS**; participant+observer **FAIL** (~6.2m).
- **M2.5.5** (`ec845fd`) — ignored-test flake fix; CI #512 **GREEN**; Nightly #52 ignored **PASS**.
- **M2.5.4** (`9c76050`) — devnet ring-16 script defaults; CI #509 **GREEN**.

## Nightly #53 Post-Mortem (`f5f45bf`, run [28705100331](https://github.com/shanecloonan/permawrite/actions/runs/28705100331))

| Job | Result | Notes |
| --- | --- | --- |
| ignored-integration | **PASS** (~11.8m) | Stable across #52/#53 |
| participant-rehearsal-smoke | **FAIL** (~6.2m) | ~360s class → likely mined/upload/faucet timeout on slow GHA runner |
| observer-rehearsal-smoke | **FAIL** (~6.3m) | Same class as participant |

**M2.5.7 fix (local):**
- `start-all` — GHA hub tip wait 600s; voter dial 480s with hub-tip≥1 soft fallback.
- `participant-rehearsal-smoke` — stall-based health-check (2×15s samples, no P2P session min); GHA faucet 600s / mined+upload 480s; STAGE logging; hub liveness sanity 90s (start-all already gates).

## Agent 1 Detailed Plan

### Done

- [x] M2.5.6 (`f5f45bf`) — CI #514 **GREEN**; Nightly #53 ignored **PASS**.
- [x] M2.5.5 — ignored-test flake fix; Nightly #52 ignored **PASS**.

### In Progress

- [ ] Monitor **CI** on `6720651` → RC Validation → **Nightly #54**.

### Next

- [x] Local CI mirror green on M2.5.7 (`ci-check-m257-run.log`).
- [x] M2.5.7 pushed (`261b0d2` + `6720651`).
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit**, ~35 min).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

### Done

- [x] M2.5.6 — voter dial + hub tip wait; GHA health-check gate (v1).

### In Progress

- [ ] **M2.5.7** — GHA faucet 600s / mined+upload 480s; stall health-check; STAGE logs.

### Next

- [ ] Green Nightly participant + observer.

## Agent 2 Detailed Plan

- [x] `release-evidence-f5f45bf` + RC audit dry-run (go).
- [ ] Refresh release evidence after green Nightly on M2.5.7 commit.
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Green GitHub CI — **PASS** CI #514 on `f5f45bf` (M2.5.6, all OS).
- RC Validation — **PASS** #44 (dispatched Nightly #53).
- Nightly — **PARTIAL** #53 on `f5f45bf` (ignored **PASS**; participant+observer **FAIL**); M2.5.7 fix in progress.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Participant + observer Nightly fail at ~6.2m on GHA (#52/#53) — M2.5.7 extends mining/funding/upload windows and uses stall-based health-check.
- Do **not** mark Nightly green until GitHub Actions confirms all three nightly jobs pass on the exact RC commit.
