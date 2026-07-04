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
| Agent 1 | Core protocol, consensus, economics | **M2.5.4** (`9c76050`). | **Done** — CI #509 **GREEN** (all OS). | Monitor Nightly #51 on `9c76050`. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.4** evidence. | **Done** — `release-evidence-9c76050` + RC audit dry-run. | Operator sign-off after Nightly green. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.4** devnet scripts. | **Done** — fund-wallet/participant-rehearsal default ring-16. | Nightly participant+observer green. |

## Recently Completed

- **M2.5.4** (`9c76050`) — devnet ring-16 script defaults; CI #509 **GREEN**; RC Validation #39 → Nightly #51.
- **M2.5.3** (`95739e4`) — node/mempool ring-16 harness; CI #505 **GREEN** (all OS).
- **Nightly #49** — ignored smokes **PASS**; participant + observer **FAIL** (`--ring-size 8` vs CLI min 16).
- **M2.5.0** (`0e10470`) — ring-16 privacy + operator-direct SPoRA coinbase.

## Agent 1 Detailed Plan

### Done

- [x] M2.5.0–M2.5.3 core, integration, mempool ring-16 alignment.
- [x] **M2.5.4** pushed (`9c76050`) — devnet script ring-16 defaults; CI #509 green; RC Validation #39 → Nightly #51.

### In Progress

- [ ] Monitor Nightly #51 on `9c76050` (participant + observer + ignored).

### Next

- [ ] Nightly green (participant + observer + ignored).
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit**, ~35 min).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

### Done

- [x] CLI/wallet/mempool ring-16; M2.5.4 devnet funding/rehearsal script defaults.

### Next

- [ ] Full green Nightly #51 (participant + observer + ignored).

## Agent 2 Detailed Plan

- [x] `release-evidence-95739e4` + RC audit dry-run (go).
- [x] `release-evidence-9c76050` + RC audit dry-run (go).
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Green GitHub CI — **PASS** CI #509 on `9c76050` (M2.5.4, all OS).
- RC Validation — **PASS** #39 (dispatched Nightly #51 on `9c76050`).
- Nightly — **IN PROGRESS** #51 on `9c76050`; #49/#50 **FAIL** (pre-fix ring-size 8).
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Nightly #49/#50 failed on pre-fix ring-size 8; M2.5.4 fix + Nightly #51 dispatched via RC Validation #39.
