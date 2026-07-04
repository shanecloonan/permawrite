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
| Agent 1 | Core protocol, consensus, economics | **M2.5.6** devnet quorum + block-production gates. | **Done** — `f5f45bf` pushed; local CI mirror **GREEN** (`ci-check-m256b.log`). | Monitor CI #514 → RC Validation → Nightly #53. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.5** evidence (`ec845fd`). | **Done** — `release-evidence-ec845fd` + RC audit dry-run (go). | Refresh evidence after green Nightly on `f5f45bf`. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.6** rehearsal hardening. | **Done** — GHA health-check gate + extended timeouts in `f5f45bf`. | Nightly participant+observer green on `f5f45bf`. |

## Recently Completed

- **M2.5.6** (`f5f45bf`) — voter dial wait + hub tip wait in `start-all`; GHA health-check gate; extended rehearsal timeouts; local CI mirror **GREEN**.
- **M2.5.5** (`ec845fd`) — ignored-test flake fix + devnet CI liveness v1; CI #512 **GREEN**; Nightly #52 ignored **PASS**.
- **M2.5.4** (`9c76050`) — devnet ring-16 script defaults; CI #509 **GREEN**.
- **Nightly #51** — **FAIL** on `9c76050` (all jobs; triaged → M2.5.5).

## Nightly #52 Post-Mortem (`ec845fd`, run [28702756921](https://github.com/shanecloonan/permawrite/actions/runs/28702756921))

| Job | Result | Notes |
| --- | --- | --- |
| ignored-integration | **PASS** (~11.8m) | M2.5.5 sortition flake fix confirmed |
| participant-rehearsal-smoke | **FAIL** (~6.0m) | Hub block production / faucet funding timeout on slow Linux runner |
| observer-rehearsal-smoke | **FAIL** (~6.2m) | Same class as participant |

**M2.5.6 fix (`f5f45bf`, pushed):**
- `start-all` — `wait_voter_dial_hub` (300s GHA) before observer; `wait_hub_tip_at_least` (480s GHA) before return.
- `participant-rehearsal-smoke` — GHA `health-check.sh` gate (`MFN_HEALTH_REQUIRE_ALL_ROLES=0`, `MFN_HEALTH_MIN_P2P_SESSIONS=2`); hub liveness 480s; faucet 480s; mined 360s.
- `permanence-demo` — GHA upload stall abort 240s (was 120s).
- `nightly.yml` — observer catchup/min-hub-height waits 420s (was 300s).

## Agent 1 Detailed Plan

### Done

- [x] M2.5.6 (`f5f45bf`) — voter dial + hub tip wait; local CI mirror green.
- [x] M2.5.5 (`ec845fd`) — ignored-test flake fix; CI #512 **GREEN**; Nightly #52 ignored **PASS**.

### Next

- [ ] GitHub CI green on `f5f45bf` (CI #514 in progress).
- [ ] RC Validation → Nightly #53 all jobs green.
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit**, ~35 min).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

### Done

- [x] M2.5.6 (`f5f45bf`) — voter dial + hub tip wait; GHA health-check; extended timeouts.

### Next

- [ ] Green Nightly participant + observer on `f5f45bf`.

## Agent 2 Detailed Plan

- [x] `release-evidence-ec845fd` + RC audit dry-run (go).
- [ ] Refresh release evidence after green Nightly on M2.5.6 commit.
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Green GitHub CI — **IN PROGRESS** CI #514 on `f5f45bf` (M2.5.6).
- RC Validation — pending green CI #514.
- Nightly — **PARTIAL** #52 on `ec845fd`; awaiting #53 on `f5f45bf`.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Participant + observer Nightly still failing on slow GitHub Actions runners despite M2.5.5 hub liveness wait — M2.5.6 adds block-production gate in `start-all`.
- Do **not** mark Nightly green until GitHub Actions confirms all three nightly jobs pass on the exact RC commit.
