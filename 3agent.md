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
| Agent 1 | Core protocol, consensus, networking, sync | **M2.4.78** RC validation automation. | **In progress** — `rc-validation-after-ci.yml` + Linux soak dispatch path. | Archive Linux soak artifact after workflow. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | **M2.4.78** CI monitor `d6298d4`. | **In progress** — queue cleanup green; CI running. | Release-evidence for green commit. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | **M2.4.78** Nightly archive evidence. | **In progress** — bash `--archive-evidence` + Nightly job update. | Confirm Nightly green on exact CI commit. |

## Recently Completed

- Agent 1: **M2.4.77** — CI queue cleanup UTF-8 fix; stale runs cancelled (`d6298d4`).
- Agent 1: **M2.4.76** — upload transport retry, dispatch REST fallback, observer evidence UTF-8.
- Agent 1: **M2.4.70** — Windows 30s-slot soak PASS height 38 + RESTART.

## Agent 1 Detailed Plan

### Done (M2.4.64–M2.4.77)

- [x] Windows 30s-slot soak PASS + soak lock + archive evidence.
- [x] CI queue cleanup cancels stale runs (UTF-8 workflow fix).
- [x] Linux Soak Audit workflow.

### In Progress (M2.4.78)

- [ ] `rc-validation-after-ci.yml` auto-dispatch Nightly on green CI push.
- [ ] Linux `--archive-evidence` parity on `participant-rehearsal-smoke.sh` + Nightly jobs.

### Next

- [ ] Manual **Linux Soak Audit** dispatch once CI green (`dispatch-rc-workflows.ps1 -LinuxSoakAudit`).
- [ ] Commit archived Linux 30s-slot soak evidence from workflow artifact.

## Agent 3 Detailed Plan

- [x] Windows observer rehearsal PASS + `-ArchiveEvidence` (UTF-8 no BOM).
- [ ] Nightly jobs archive Linux rehearsal evidence (`--archive-evidence`).
- [ ] First green **Nightly** triggered by RC validation workflow on green CI commit.

## Agent 2 Detailed Plan

- [x] `release-evidence-ad18d94` + RC audit decision=go.
- [ ] Regenerate release-evidence for latest green CI commit.
- [ ] Operator human sign-off on release inventory.

## Shared Release-Candidate Gates

- Exact commit has green GitHub CI.
- Local CI mirror passed.
- Nightly + ci-ignored smoke coverage for release candidates.
- `release-evidence.md` / `.json` for exact commit.
- RC audit dry-run packet archived (`decision=go`).
- Linux 30s-slot soak evidence (Windows done; Linux workflow pending).
- Support bundle + archive validation + human sign-off.

## Cross-Agent Blockers

- Linux 30s-slot soak still requires manual workflow dispatch (90min job; not auto on every CI green).
