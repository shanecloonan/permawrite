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
| Agent 1 | Core protocol, consensus, economics | **M2.5.5** Nightly #51 fix. | **Pushed** — ignored-test flake + devnet CI liveness hardening; await CI #512 + Nightly #52. | RC Validation → Nightly #52 green. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.4** evidence (`6936c47`). | **Done** — release evidence + RC audit on `9c76050`. | Refresh evidence after green Nightly on M2.5.5 commit. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.5** devnet CI hardening. | **Pushed** — voter readiness poll + hub liveness wait in rehearsal smoke. | Nightly participant+observer green. |

## Recently Completed

- **M2.5.4** (`9c76050`/`6936c47`) — devnet ring-16 script defaults; CI #509 **GREEN**; release evidence archived.
- **M2.5.3** (`95739e4`) — node/mempool ring-16 harness; CI #505 **GREEN** (all OS).
- **Nightly #49** — ignored smokes **PASS**; participant + observer **FAIL** (pre-fix `--ring-size 8`).
- **M2.5.0** (`0e10470`) — ring-16 privacy + operator-direct SPoRA coinbase.

## Nightly #51 Post-Mortem (`9c76050`, run [28700355365](https://github.com/shanecloonan/permawrite/actions/runs/28700355365))

All three jobs **FAIL** (~6m, not full ~11m pass):

| Job | Failed step | Root cause (confirmed) |
| --- | --- | --- |
| ignored-integration | `cargo test --ignored` | `three_validators_all_produce_converge_on_shared_tip` — flaky stdout grep for `mfnd_producer_slot_skip/advance` under 1.5-proposer sortition |
| participant-rehearsal-smoke | rehearsal smoke (~5m) | Likely hub liveness / faucet reward timeout (ring-16 scripts OK; failure timing matches 90s start + 360s faucet window) |
| observer-rehearsal-smoke | observer smoke (~5m) | Same class as participant (hub height / observer catchup) |

**M2.5.5 fix plan:** remove flaky sortition log assertion (covered elsewhere); `start-all` waits for committee voter P2P before returning; `participant-rehearsal-smoke` adds explicit hub `tip_height >= 1` wait + longer CI faucet window.

## Agent 1 Detailed Plan

### Done

- [x] M2.5.0–M2.5.4 core, integration, mempool, devnet script ring-16 alignment.
- [x] Nightly #51 triage — all three jobs failed; root causes identified.

### In Progress

- [ ] **M2.5.5** — ignored-test flake fix + devnet startup/rehearsal CI hardening (**pushed**; await CI + Nightly #52).

### Next

- [ ] Local CI mirror green on M2.5.5.
- [ ] Push → wait CI green → RC Validation → Nightly #52 on exact commit.
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit**, ~35 min).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

### Done

- [x] CLI/wallet/mempool ring-16; M2.5.4 devnet funding/rehearsal script defaults.

### In Progress

- [ ] **M2.5.5** — `start-all` voter P2P readiness; rehearsal smoke hub liveness + CI wait tuning (**pushed**).

### Next

- [ ] Green Nightly participant + observer on fix commit.

## Agent 2 Detailed Plan

- [x] `release-evidence-95739e4` + RC audit dry-run (go).
- [x] `release-evidence-9c76050` + RC audit dry-run (go) on `6936c47`.
- [ ] Refresh release evidence after Nightly green on M2.5.5 commit.
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Green GitHub CI — **PASS** CI #509 on `9c76050`; CI #511 on `6936c47` (docs-only). M2.5.5 fix commit — await CI #512.
- RC Validation — **PASS** #39 (dispatched Nightly #51).
- Nightly — **FAIL** #51 on `9c76050` (all jobs); #49/#50 **FAIL** (pre-fix ring-size 8).
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Nightly #51 blocked RC on `9c76050` despite ring-16 script fix — ignored-test flake + devnet CI liveness, not ring-size regression.
- Do **not** mark Nightly green until GitHub Actions confirms all three nightly jobs pass on the exact RC commit.
