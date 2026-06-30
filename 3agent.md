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
| Agent 1 | Core protocol, consensus, networking, sync | Boot-dial connect quarantine follow-up is observed in local work but not owned by Agent 2. | In progress outside this lane. | Land deterministic coverage that quarantined boot-dial connect failures suppress reconnect spawning before cap accounting. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | Release archive manifest validation for staged public artifacts. | Completed locally; local CI mirror passed. | Add GitHub CI watcher/sign-off helper that blocks release approval until the exact pushed commit is green. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | Participant rehearsal and permanence UX are mostly in place. | Next hardening item remains pending. | Promote participant rehearsal smoke into unattended slow/nightly coverage once mesh runtime is stable enough for CI. |

## Recently Completed

- Agent 2: Release evidence tooling, JSON schema/sample, support-bundle evidence validation, sign-off review, dry-run sign-off flow, artifact inventory, checksum helpers, inventory validation, archive layout guidance, and archive assembly dry-run helper are landed on `main`.
- Agent 2: Release archive validation scripts now verify staged public files, checksum manifests, and obvious private filename exclusions before publication.
- Agent 1: Recent `main` commits landed outbound P2P connect bounds, boot peer list capping, and boot cap startup log coverage.
- Agent 3: Recent `main` commits landed participant rehearsal smoke and faucet reward wait hardening.

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

Current task:

- [x] Create shared `3agent.md` coordination file.
- [x] Add release archive validation scripts for staged public artifacts.
- [x] Add CI coverage that validates dry-run archive output and rejects corrupted checksums.
- [x] Update `docs/TESTNET_CHECKLIST.md`, `docs/TESTNET.md`, `docs/RELEASE_ARTIFACT_INVENTORY_TEMPLATE.md`, and `scripts/public-devnet-v1/OPERATORS.md`.
- [x] Regenerate `CODEBASE_STATS.md` and run the local CI mirror.
- [ ] Commit, push, and check GitHub CI.

Next Agent 2 task:

- [ ] Add release-candidate GitHub CI watcher guidance or helper that blocks sign-off until the exact pushed commit is green.
