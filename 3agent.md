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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.66** devnet mesh isolation + soak evidence. | **Shipped** — Windows soak SUMMARY PASS + `soak: RESTART` archived (height 28). | Agent 3: nightly rehearsal promotion. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | GitHub CI monitor + release gates. | Monitor CI on M2.4.66 commit. | Archive validation on green CI. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | Participant rehearsal evidence fixture. | **PASS** on M2.4.64 (`20260703T113642Z`). Soak green unblocks promotion. | Promote rehearsal smoke to slow/nightly CI. |

## Recently Completed

- Agent 1: **M2.4.66** — devnet-ports mutex + merge-from-disk; stop-all no longer deletes ports by default; soak foreign-mfnd preflight; iteration budget fix; **Windows soak PASS** (`evidence/soak-restart-windows-20260703T120117Z.txt`).
- Agent 1: **M2.4.65** — observer RPC fallback in health-check; soak retries connection refused (`511b2b7` / `b7ef72b`).
- Agent 1: **M2.4.64** — sync proposal fan-out, catch-up idle skip, bounded inbound workers (`2592d03`).
- Agent 3: **participant-rehearsal-smoke PASS** on M2.4.64 (fund-wallet height 2, permanence-demo, support bundle `20260703T113642Z`).

## Agent 1 Detailed Plan

### Done (M2.4.64 / M2.4.65 / M2.4.66)

- [x] `fanout_proposal_sync`, extended pending release with votes, `periodic_catch_up_idle`, inbound cap 48.
- [x] Observer RPC fallback in health-check (log rescrape + ports refresh).
- [x] Devnet-ports mutex + merge-from-disk `Set-DevnetPort`; start-all owns clean slate.
- [x] `start-all.ps1` calls `stop-all.ps1` (recorded PIDs only); soak warns on foreign `mfnd`.
- [x] Soak iteration budget matches stall sampling; retries transient stall/divergence.
- [x] Participant rehearsal smoke PASS on M2.4.64.
- [x] Windows `soak.ps1 -RestartObserverOnce` SUMMARY PASS + archived `soak: RESTART` evidence (height 28).

### Next

- [ ] Agent 3: promote participant rehearsal smoke to slow/nightly CI.
- [ ] Participant rehearsal smoke PASS past height 5 with observer enabled (stretch).
- [ ] Long-run hub daemon lifetime audit under 30s-slot public devnet config.

## Agent 3 Detailed Plan

- [x] Harden `permanence-demo` upload-index wait; 10s slot smoke defaults.
- [x] Participant rehearsal smoke PASS on M2.4.64.
- [ ] Capture public-devnet participant evidence fixture from successful live rehearsal.
- [ ] Promote participant rehearsal smoke into slow/nightly CI (unblocked by soak green).

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI.
- Local CI mirror passed on the release host or equivalent clean machine.
- Ignored/nightly smoke coverage is run for public-devnet release candidates.
- `CODEBASE_STATS.md` regenerated after final changes.
- `release-evidence.md` and `release-evidence.json` generated for the exact commit.
- Support bundle includes valid `release-evidence.v1` JSON.
- Artifact inventory is filled, reviewed, and validated.
- Release archive is staged, checksum-validated, and reviewed as public-only.
- Security docs still say pre-audit experimental and do not imply production safety.
- RPC remains loopback/private unless a written firewall/TLS/API-key exception has an owner.

## Agent 2 Detailed Plan

- [ ] Monitor GitHub CI on M2.4.66 commit.
- [ ] Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md`.
