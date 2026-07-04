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
| Agent 1 | Core protocol, consensus, economics | **M2.5.17** Windows voter-dial parity. | **Done** (local) — `start-all.ps1` GHA voter dial 600s. | Push → await CI #542. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.16** evidence refresh. | **Done** — `4ece816`/`4987913`; **CI #541 GREEN**. | Run `release-evidence-refresh-for-head` on `4987913`. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.16** assert + refresh stack. | **Done** — on `main`. | Monitor **Nightly #55** on `4987913`. |

## Recently Completed

- **M2.5.17** (pushing) — `start-all.ps1` GHA voter hub-dial timeout 600s (bash parity; was 480s).
- **M2.5.16** (`4ece816`) — schema-validate `release-evidence-refresh-for-head` output.
- **M2.5.15** (`e6ba99e`) — `release-evidence-refresh-for-head`; nightly assert GHA step summary.
- **M2.5.14** (`c55153f`) — ci-check RC dry-run coverage; nightly failure log tail.
- **M2.5.13** (`0afa61b`) — RC dry-run assert gate; nightly partial evidence upload on failure.
- **M2.5.12** (`aa25d26`/`9434ff5`) — `assert-participant-smoke-evidence.{sh,ps1}` gates nightly upload; CI positive/negative coverage.
- **M2.5.11** (`08bbf7b`) — nightly uploads audit-ready `participant-rehearsal-smoke/evidence/`; TESTNET.md `-ParticipantEvidenceDir` guidance.
- **M2.5.10** (`994d1a9`) — `-ParticipantEvidenceDir` on release-audit-packet for smoke→audit handoff.
- **M2.5.9** (`96327da`/`318407a`) — shared `query_tip_height` with get_status fallback.
- **M2.5.8** (`4dbd5c7`/`eb64408`) — 600s GHA startup polls; single-sample health-check.

## Nightly #54 Post-Mortem (`6720651` via `d08dcca`, run [28707532689](https://github.com/shanecloonan/permawrite/actions/runs/28707532689))

| Job | Result | Notes |
| --- | --- | --- |
| ignored-integration | **PASS** (~12.4m) | Stable |
| participant-rehearsal-smoke | **FAIL** (~6.3m) | Legacy 300s hub P2P poll — fixed in M2.5.8 |
| observer-rehearsal-smoke | **FAIL** (~6.3m) | Same class |

## Agent 1 Detailed Plan

### Done

- [x] M2.5.8 — 600s GHA startup polls; Nightly #54 post-mortem.
- [x] M2.5.9 — shared `query_tip_height` on `main`.

- [x] M2.5.17 — Windows `start-all.ps1` GHA voter dial 600s parity.

### Next

- [ ] **Nightly #55** on `4987913` (RC Validation after CI #541 green).
- [ ] Linux 30s-slot soak (manual **Linux Soak Audit**).
- [ ] Operator sign-off.

## Agent 3 Detailed Plan

### Done

- [x] M2.5.7 — STAGE logging, faucet 600s / mined+upload 480s, stall health-check v1.
- [x] M2.5.8 — single-sample health-check; curl RPC fallback; hub tip≥2; 600s GHA startup polls.
- [x] M2.5.9 — fund-wallet/permanence-demo tip query parity.
- [x] M2.5.10 — smoke evidence dir + `-ParticipantEvidenceDir` on release-audit-packet.
- [x] M2.5.11 — nightly uploads audit-ready smoke evidence; TESTNET.md handoff docs.
- [x] M2.5.12 — assert audit-ready smoke evidence before nightly upload; CI negative coverage.
- [x] M2.5.13 — RC dry-run assert gate; nightly partial evidence upload on failure.
- [x] M2.5.14 — ci-check `release-rc-audit-dry-run`; nightly failure dumps tail `participant-rehearsal.log`.
- [x] M2.5.15 — `release-evidence-refresh-for-head`; nightly assert GHA step summary.

- [x] M2.5.16 — schema-validate refresh output before CI gate.

### Next

- [ ] Monitor **Nightly #55** on `4987913`; confirm assert gate on participant+observer.

## Agent 2 Detailed Plan

- [x] `release-evidence-f5f45bf` + RC audit dry-run (go).
- [ ] Refresh release evidence after green CI + Nightly on current RC commit.
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Green GitHub CI — **GREEN** CI #541 on `4987913` (M2.5.16 `4ece816`).
- RC Validation — should dispatch **Nightly #55** on `4987913`.
- Nightly — **PARTIAL** #54; awaiting **#55** with M2.5.8+ + M2.5.9 tip fallback.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Nightly #52–#54 failed at ~302s (legacy hub P2P poll); M2.5.8+ fixes landed — **Nightly #55** is confirmation gate.
- Batch M2.5.17 push after CI #541 green (do not cancel Nightly #55 dispatch window).
- Do **not** mark Nightly green until GitHub Actions confirms all three nightly jobs pass on the exact RC commit.
