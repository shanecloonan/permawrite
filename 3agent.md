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
| Agent 1 | Core protocol, consensus, economics | **M2.5.9** tip poll fallback. | **Done** — `318407a` pushed; `96327da` local (fund-wallet/permanence parity). | Push `96327da` after CI #524 green. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.7** evidence. | **Done** — `release-evidence-f5f45bf`. | Refresh evidence after green Nightly. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.9** hub tip polls. | **In progress** — fund-wallet/permanence-demo shared tip query. | Nightly participant+observer green. |

## Recently Completed

- **M2.5.7** (`6720651`/`d08dcca`) — health-check retry + extended GHA timeouts; CI #515 **GREEN**; Nightly #54 ignored **PASS**; participant+observer **FAIL** (~6.3m).
- **M2.5.6** (`f5f45bf`) — voter dial + hub tip wait; CI #514 **GREEN**; Nightly #53 ignored **PASS**.
- **M2.5.5** (`ec845fd`) — ignored-test flake fix; Nightly #52 ignored **PASS**.

## Nightly #54 Post-Mortem (`6720651` via `d08dcca`, run [28707532689](https://github.com/shanecloonan/permawrite/actions/runs/28707532689))

| Job | Result | Notes |
| --- | --- | --- |
| ignored-integration | **PASS** (~12.4m) | Stable |
| participant-rehearsal-smoke | **FAIL** (~6.3m) | Same ~6.3m class as #52/#53 — early startup gate, not full 600s faucet window |
| observer-rehearsal-smoke | **FAIL** (~6.3m) | Same class as participant |

**Root-cause confirmed (Nightly #54 API timing):**
- Smoke step duration **302s** — matches legacy `HUB_POLL_MAX=300` on GHA (`6720651`/`d08dcca`); hub never printed `mfnd_p2p_listening=` before timeout.
- **Fixed in `eb64408`:** all GHA startup polls **600s** (hub P2P, voter P2P, voter dial, observer RPC).

**M2.5.8 on `4dbd5c7` (includes `eb64408`):**
- GHA poll caps **600s** for hub P2P, voter P2P, observer RPC, voter dial.
- Health-check: **single-sample** only (`STALL_SAMPLES=1`, no height-delta requirement); **curl JSON-RPC fallback** when `nc` missing.
- `permanence-demo` — GHA upload-index stall_abort **480s**.

## Agent 1 Detailed Plan

### Done

- [x] M2.5.7 pushed; CI #515 **GREEN**; Nightly #54 ignored **PASS**.
- [x] Nightly #54 triaged — persistent ~6.3m failure class identified.

### In Progress

- [ ] CI #524 green on `318407a` → push `96327da` + docs → RC Validation → Nightly #55.

### Next

- [ ] Green Nightly #55 (600s hub poll + tip query fallback).
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit**, ~35 min).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

### Done

- [x] M2.5.7 — STAGE logging, faucet 600s / mined+upload 480s, stall health-check v1.

### Done

- [x] **M2.5.8** — single-sample health-check; curl RPC fallback; hub tip≥2; 600s GHA startup polls.

### Next

- [ ] Green Nightly participant + observer on `4dbd5c7`.

## Agent 2 Detailed Plan

- [x] `release-evidence-f5f45bf` + RC audit dry-run (go).
- [ ] Refresh release evidence after green Nightly on M2.5.8 commit.
- [ ] Operator sign-off after Nightly + Linux soak.

**M2.5.9 fix (local):**
- `ports-env-lib.sh` — shared `query_tip_height` via mfn-cli with nc/curl get_status fallback.
- `start-all`, `participant-rehearsal-smoke`, `fund-wallet`, `permanence-demo` — use shared tip query (fixes silent `unknown` tip on GHA when mfn-cli tip RPC flakes).

## Shared Release-Candidate Gates

- Green GitHub CI — **IN PROGRESS** CI #524 on `318407a` (M2.5.9).
- RC Validation — pending green CI on M2.5.9 commit.
- Nightly — **PARTIAL** #54; awaiting **#55** with M2.5.8+ (`eb64408`) + M2.5.9 tip query fallback.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Participant + observer Nightly fail at ~6.3m on GHA (#52/#53/#54) — M2.5.8 addresses hub poll timeout + stall health-check false negatives.
- Do **not** mark Nightly green until GitHub Actions confirms all three nightly jobs pass on the exact RC commit.
