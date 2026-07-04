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
| Agent 1 | Core protocol, consensus, economics | **M2.5.8** Nightly #54 fix. | **In progress** — hub tip≥2 + upload stall 480s. | CI mirror → push → Nightly #55. |
| Agent 2 | Security, RPC, ops, release evidence | **M2.5.7** evidence (`6720651`). | **Done** — CI #519 green; Nightly #54 participant+observer **FAIL** (~6.3m). | Refresh evidence after green Nightly. |
| Agent 3 | Wallet, storage, faucet, onboarding | **M2.5.8** GHA rehearsal. | **In progress** — explicit nightly timeouts; permanence-demo stall 480s. | Nightly participant+observer green. |

## Recently Completed

- **M2.5.7** (`6720651`) — GHA rehearsal timeout extensions + stall health-check; CI #519 **GREEN**; Nightly #54 participant+observer **FAIL** (~6.3m, same class as #53).
- **M2.5.6** (`f5f45bf`) — voter dial + hub tip wait; CI #514 **GREEN**; Nightly #53 ignored **PASS**.
- **M2.5.5** (`ec845fd`) — ignored-test flake fix; CI #512 **GREEN**.

## Nightly #54 Post-Mortem (`d08dcca`, run [28707532689](https://github.com/shanecloonan/permawrite/actions/runs/28707532689))

| Job | Result | Notes |
| --- | --- | --- |
| ignored-integration | **PASS** (in progress at check) | Stable |
| participant-rehearsal-smoke | **FAIL** (~6.3m) | Same ~378s wall clock as #52/#53 → likely `permanence-demo` upload stall_abort=240s or pre-upload timeout class |
| observer-rehearsal-smoke | **FAIL** (~6.3m) | Same class as participant |

**M2.5.8 fix (local):**
- `start-all` — GHA requires hub tip_height ≥ 2 before rehearsal (sustained production).
- `permanence-demo` — GHA upload-index stall_abort 240s → 480s.
- `participant-rehearsal-smoke` — GHA proof wait 480s; health-check stall interval 20s.
- `nightly.yml` — explicit `--wait-faucet-seconds 600` / mined / upload / proof 480s on both rehearsal jobs.

## Shared Release-Candidate Gates

- Green GitHub CI — **PASS** CI #519 on `d08dcca` (M2.5.7, all OS).
- RC Validation — **PASS** (dispatched Nightly #54).
- Nightly — **PARTIAL** #54 on `d08dcca` (participant+observer **FAIL**); M2.5.8 fix in progress.
- Linux 30s-slot soak — Windows done; Linux manual dispatch pending.
- Human sign-off — pending.

## Cross-Agent Blockers

- Participant + observer Nightly fail at ~6.3m on GHA (#52–#54) — M2.5.8 extends upload stall window and requires hub tip≥2 before funding.
- Do **not** mark Nightly green until GitHub Actions confirms all three nightly jobs pass on the exact RC commit.
