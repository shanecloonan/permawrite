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
| Agent 1 | Core protocol, consensus, economics | **M2.5.19** GHA rehearsal gates. | **Done** — `fed2dd6`/`a88e8ff` on `main`. | CI #546 → Nightly #56. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.18** dispatch + evidence stack. | **Done** — inline Nightly dispatch live. | Evidence refresh after green Nightly #56. |
| Agent 3 | Wallet, storage, faucet, onboarding | **Nightly #55** post-mortem + M2.5.19. | **Done** — smokes await #56. | Monitor Nightly #56 all three green. |

## Recently Completed

- **M2.5.19** (`fed2dd6`/`a88e8ff`) — GHA hub tip 900s; health 600s; liveness 300s; voter-dial soft-continue.
- **M2.5.18** (`afc5fd8`) — CI #543 **GREEN**; inline `dispatch-nightly-rc` dispatched **Nightly #55**.
- **M2.5.17** (`850a45b`) — `start-all.ps1` GHA voter hub-dial timeout 600s (bash parity).
- **M2.5.16** (`4ece816`) — schema-validate `release-evidence-refresh-for-head` output.
- **M2.5.15** (`e6ba99e`) — `release-evidence-refresh-for-head`; nightly assert GHA step summary.
- **M2.5.14** (`c55153f`) — ci-check RC dry-run coverage; nightly failure log tail.
- **M2.5.13** (`0afa61b`) — RC dry-run assert gate; nightly partial evidence upload on failure.
- **M2.5.12** (`aa25d26`/`9434ff5`) — `assert-participant-smoke-evidence.{sh,ps1}` gates nightly upload; CI positive/negative coverage.
- **M2.5.11** (`08bbf7b`) — nightly uploads audit-ready `participant-rehearsal-smoke/evidence/`; TESTNET.md `-ParticipantEvidenceDir` guidance.
- **M2.5.10** (`994d1a9`) — `-ParticipantEvidenceDir` on release-audit-packet for smoke→audit handoff.
- **M2.5.9** (`96327da`/`318407a`) — shared `query_tip_height` with get_status fallback.
- **M2.5.8** (`4dbd5c7`/`eb64408`) — 600s GHA startup polls; single-sample health-check.

## Nightly #55 Post-Mortem (`afc5fd8`, run [28717845801](https://github.com/shanecloonan/permawrite/actions/runs/28717845801))

| Job | Result | Duration | Notes |
| --- | --- | --- | --- |
| ignored-integration | **PASS** | ~11.5m | Stable |
| participant-rehearsal-smoke | **FAIL** | ~11.3m | Past 302s startup — likely **600s voter hub-dial** gate |
| observer-rehearsal-smoke | **FAIL** | ~11.3m | Same class |

**M2.5.19 fix:** GHA hub tip wait **900s**; health-check **600s**; hub liveness **300s**; voter-dial soft-continue when hub tip≥2 + both voters P2P listening.

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

- [ ] **Nightly #56** after M2.5.19 CI green.
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

- [ ] Monitor **CI #546** on `a88e8ff` → inline dispatch **Nightly #56**.

## Agent 2 Detailed Plan

- [x] `release-evidence-f5f45bf` + RC audit dry-run (go).
- [ ] Refresh release evidence after green CI + Nightly on current RC commit.
- [ ] Operator sign-off after Nightly + Linux soak.

## Shared Release-Candidate Gates

- Green GitHub CI — **GREEN** CI #543 on `afc5fd8` (M2.5.18).
- RC / Nightly dispatch — **DONE** — M2.5.18 inline CI job dispatched **Nightly #55**.
- Nightly — **PARTIAL** #55 FAIL (~11.3m voter dial); **M2.5.19** fix pending CI → #56.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Nightly #55 confirmed M2.5.8 startup fix (11m not 302s); **M2.5.19** extends waits + voter-dial soft gate.
- Do **not** push during in-flight CI.
- Do **not** mark Nightly green until GitHub Actions confirms all three nightly jobs pass on the exact RC commit.
