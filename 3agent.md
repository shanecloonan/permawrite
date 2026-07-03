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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.68** observer rehearsal evidence. | **Shipped** — Windows PASS hub≥5 + observer catch-up archived. | 30s-slot long-run hub lifetime audit. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | GitHub CI monitor + release gates. | Monitor CI on M2.4.68; `gh auth login` needed locally. | Archive validation; first nightly smoke green. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.68** observer-enabled rehearsal smoke. | **Shipped** — `-WithObserver -MinHubHeight 5` PASS + evidence. | Confirm Linux nightly rehearsal smoke green. |

## Recently Completed

- Agent 3: **M2.4.68** — observer-enabled participant rehearsal smoke (`-WithObserver`, min hub height + observer catch-up waits); Windows PASS archived (`evidence/participant-rehearsal-observer-windows-20260703T123639Z.txt`).
- Agent 3: **M2.4.67** — nightly + `ci-ignored` real-run smoke; evidence fixture `participant-rehearsal-evidence-v1`.
- Agent 1: **M2.4.66** — Windows soak SUMMARY PASS + `soak: RESTART` archived (height 28).

## Agent 1 Detailed Plan

### Done

- [x] M2.4.66 soak RESTART evidence; M2.4.67 nightly promotion.
- [x] M2.4.68 observer rehearsal PASS past height 5 (Agent 3 lane, archived evidence).

### Next

- [ ] Long-run hub daemon lifetime audit under 30s-slot public devnet config.
- [ ] Monitor first green nightly `participant-rehearsal-smoke` on Linux CI.

## Agent 3 Detailed Plan

- [x] Nightly participant-rehearsal-smoke promotion (M2.4.67).
- [x] Observer-enabled rehearsal PASS with `min_hub_height >= 5` (M2.4.68).

### Next

- [ ] Confirm Linux nightly rehearsal smoke green on GitHub Actions.
- [ ] Optional staging: nightly observer variant after Linux green.

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

- [ ] Monitor GitHub CI on M2.4.68 commit (`gh auth login` or Actions UI).
- [ ] Monitor first nightly `participant-rehearsal-smoke` run (`gh workflow run Nightly`).
- [ ] Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md`.
