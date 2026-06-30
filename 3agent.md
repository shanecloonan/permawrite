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
| Agent 1 | Core protocol, consensus, networking, sync | Gap-triggered catch-up planning filters quarantined peers before recovery dial cap accounting. | In progress in clean Agent 1 worktree. | Add deterministic coverage that gap-triggered recovery dial failures feed peer scoring labels. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | Dependency-free JSON schema validation for published release artifacts. | Completed locally; local CI mirror passed. | Add full third-party Draft 2020-12 validation if a validator dependency is pinned in the release toolchain. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | Participant rehearsal and permanence UX are mostly in place. | Next hardening item remains pending. | Promote participant rehearsal smoke into unattended slow/nightly coverage once mesh runtime is stable enough for CI. |

## Recently Completed

- Agent 2: Release evidence tooling, JSON schema/sample, support-bundle evidence validation, sign-off review, dry-run sign-off flow, artifact inventory, checksum helpers, inventory validation, archive layout guidance, and archive assembly dry-run helper are landed on `main`.
- Agent 2: Release archive validation scripts now verify staged public files, checksum manifests, and obvious private filename exclusions before publication.
- Agent 2: Release CI watcher scripts now fail closed unless the exact commit has green GitHub CI.
- Agent 2: Release sign-off manifest scripts combine exact-commit CI, release evidence, archive validation, artifact inventory validation, and human approvals into one machine-readable decision record.
- Agent 2: Release sign-off manifest schema/sample artifacts are published for dashboards and independent validator tooling.
- Agent 2: Release sign-off manifest validators enforce the published contract and fail `go` decisions unless all machine and human gates pass.
- Agent 2: Release JSON schema validators enforce the repository's published release schemas without adding an unpinned third-party dependency.
- Agent 1: Recent `main` commits landed outbound P2P connect bounds, boot peer list capping, boot cap startup log coverage, boot-dial connect quarantine without durable peer deletion, saved-peer reconnect quarantine before cap accounting, and committee catch-up quarantine before cap accounting.
- Agent 3: Recent `main` commits landed participant rehearsal smoke and faucet reward wait hardening.

## Agent 1 Detailed Plan

Current task:

- [x] Add cap-aware gap-triggered catch-up event planning without changing self-skip behavior.
- [x] Add deterministic `mfn-net::serve` coverage for gap self-skips, recovery dials, and cap-reached events.
- [x] Add deterministic `mfn-node::p2p_fanout` coverage that gap recovery peer sources filter quarantined peers.
- [x] Update `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and `scripts/public-devnet-v1/OPERATORS.md`.
- [x] Regenerate `CODEBASE_STATS.md`, run targeted tests, and run the local CI mirror.

Next Agent 1 task:

- [ ] Add deterministic coverage that gap-triggered recovery dial failures feed peer scoring labels.

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

- [x] Add `release-json-schema-validate.ps1` and `release-json-schema-validate.sh`.
- [x] Validate release evidence and sign-off manifest samples against their published schemas.
- [x] Add CI coverage that rejects forbidden additional properties.
- [x] Update release docs and checklist.
- [x] Regenerate `CODEBASE_STATS.md` and run local CI mirror.
- [ ] Commit, push, and check GitHub CI.

Next Agent 2 task:

- [ ] Add full third-party Draft 2020-12 validation if a validator dependency is pinned in the release toolchain.
