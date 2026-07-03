# 3agent Coordination

This file coordinates the three active Permawrite agent lanes. Keep using `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and the operator runbooks as the detailed source of truth; this file is the cross-agent handoff board for current work, completed units, and next work.

Permawrite is pre-audit experimental software. Do not mark public-testnet readiness complete until the exact release commit has green GitHub CI, local CI mirror evidence, ignored/nightly coverage where required, release evidence, archive validation, and named human sign-off.

## Update Protocol

- Update this file at the start or end of every coherent agent unit.
- Record the exact lane owner, current unit, status, blockers, and next handoff.
- Do not claim another agent's uncommitted work; mention it as "observed local work" until it lands on `main`.
- Continue updating `docs/TESTNET_CHECKLIST.md` for durable release-readiness tasks.
- Commit and push completed units to `main` after the required local CI mirror passes.

## Current Board

| Agent | Lane | Current Unit | Status | Next Handoff |
| --- | --- | --- | --- | --- |
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.73** Linux soak + bash soak lock parity. | **Done locally** — `soak.sh` success criteria, `ports-env-lib.sh`, start/stop lock. | Linux 30s-slot soak evidence capture. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.73** RC audit dry-run. | **Done locally** — `release-rc-audit-dry-run.ps1` decision=go archived. | Human sign-off + green CI on push. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.72** nightly observer rehearsal job. | **Shipped** — workflow live; awaiting first green run. | Confirm Linux nightly green (both jobs). |

## Recently Completed

- Agent 1: **M2.4.71–72** — soak criteria, release-evidence, nightly observer job (`76d6c82`).
- Agent 1: **M2.4.70** — 30s-slot soak PASS height 38 + RESTART evidence archived.
- Agent 3: **M2.4.68** — observer-enabled rehearsal PASS hub≥5 + evidence archived.
- Agent 2: **M2.4.73** — RC audit dry-run with M2.4.70 soak + participant fixture evidence.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.73)

- [x] Mesh stability, soak RESTART, devnet-ports mutex, observer rehearsal past height 5.
- [x] Soak `-MinFinalHeight` / graceful deadline exit / archive on finish (PowerShell + Bash).
- [x] Bash `ports-env-lib.sh` soak lock; `start-all.sh` / `stop-all.sh` `--force` parity.
- [x] Windows 30s-slot soak PASS — `evidence/soak-restart-windows-30s-slot-20260703T132240Z.txt`.

### Next

- [ ] Capture Linux 30s-slot soak evidence (`soak.sh --min-final-height 10 --archive-evidence`).
- [ ] Monitor nightly observer rehearsal smoke on GitHub Actions.

## Agent 3 Detailed Plan

- [x] Nightly job `participant-rehearsal-smoke-observer` with `--with-observer --min-hub-height 5`.
- [x] `ci-ignored` mirrors both nightly rehearsal jobs locally.
- [ ] Confirm first green Linux nightly for both rehearsal jobs.

## Agent 2 Detailed Plan

- [x] `release-evidence` JSON/MD for M2.4.70 commit.
- [x] `release-rc-audit-dry-run.ps1` + archived `evidence/rc-audit-dry-run-76d6c82-*.json` (decision=go).
- [x] Fix `release-evidence.ps1` null CI conclusion → empty string for schema validation.
- [ ] Monitor GitHub CI for M2.4.73 push.
- [ ] Operator human sign-off fields in release inventory.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI.
- Local CI mirror passed.
- Nightly + ci-ignored smoke coverage for release candidates.
- `release-evidence.md` / `.json` for exact commit.
- RC audit dry-run packet archived (`decision=go`).
- Support bundle + archive validation + human sign-off.
