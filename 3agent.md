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
| Agent 1 | Core protocol, consensus, networking, sync | Public-devnet local-mesh liveness when the hub logs `mfnd_producer_slot_skip` and height stalls at genesis. | Next in clean Agent 1 worktree. | Ship deterministic producer-slot coverage and fix stalled local-mesh block production. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | Offline wheelhouse guidance for air-gapped strict schema validation. | Completed locally; local CI mirror pending. | Wire wheelhouse artifacts into release-archive dry-run validation for air-gapped hosts. |
| Agent 3 | Wallet, storage, faucet/test funding, onboarding | Participant rehearsal and permanence UX are mostly in place. | Next hardening item remains pending. | Promote participant rehearsal smoke into unattended slow/nightly coverage once mesh runtime is stable enough for CI. |

## Recently Completed

- Agent 2: Release evidence tooling, JSON schema/sample, support-bundle evidence validation, sign-off review, dry-run sign-off flow, artifact inventory, checksum helpers, inventory validation, archive layout guidance, and archive assembly dry-run helper are landed on `main`.
- Agent 2: Release archive validation scripts now verify staged public files, checksum manifests, and obvious private filename exclusions before publication.
- Agent 2: Release CI watcher scripts now fail closed unless the exact commit has green GitHub CI.
- Agent 2: Release sign-off manifest scripts combine exact-commit CI, release evidence, archive validation, artifact inventory validation, and human approvals into one machine-readable decision record.
- Agent 2: Release sign-off manifest schema/sample artifacts are published for dashboards and independent validator tooling.
- Agent 2: Release sign-off manifest validators enforce the published contract and fail `go` decisions unless all machine and human gates pass.
- Agent 2: Release JSON schema validators enforce the repository's published release schemas without adding an unpinned third-party dependency.
- Agent 2: Final release audit packet helpers aggregate CI, evidence schema, sign-off, archive, inventory, and stats checks into one operator-facing go/no-go report.
- Agent 2: Release CI watcher now reports unauthenticated GitHub API rate limits as structured no-go JSON instead of crashing.
- Agent 2: Release CI watcher fallback uses `GH_TOKEN` / `GITHUB_TOKEN` for authenticated API polling without leaking tokens into JSON output.
- Agent 2: WASM package metadata is explicit where wasm-pack requires string fields, keeping the local CI mirror's wasm package build green.
- Agent 1: Recent `main` commits landed outbound P2P connect bounds, boot peer list capping, boot cap startup log coverage, boot-dial connect quarantine without durable peer deletion, saved-peer reconnect quarantine before cap accounting, committee catch-up quarantine before cap accounting, gap-triggered recovery cap accounting, stable gap recovery peer-scoring labels, gap recovery success clearing transient peer penalties, durable gap recovery peer retention, and Windows chunk auto-fanout promotion.
- Agent 2: Release audit packet schema/sample artifacts are published for dashboards and independent validator tooling.
- Agent 2: Release audit packet schema now includes participant rehearsal evidence paths, and CI validates generated packets with participant evidence.
- Agent 2: Release artifacts now have pinned `jsonschema==4.17.3` Draft 2020-12 validation wrappers in local and GitHub CI.
- Agent 2: Release-schema Python dependencies are hash-pinned and installed with `pip --require-hashes` in local and GitHub CI.
- Agent 1: Observer restart soak evidence (`soak: RESTART` with pre/post heights and RPCs) landed on `main` as M2.4.59.
- Agent 2: Release-schema Python dependencies are hash-pinned and installed with `pip --require-hashes` in local and GitHub CI.
- Agent 2: Offline wheelhouse/install helpers and operator guidance support air-gapped strict Draft 2020-12 validation.
- Agent 3: Recent `main` commits landed participant rehearsal smoke, faucet reward wait hardening, and evidence-dir release-audit handoff.

## Agent 1 Detailed Plan

Completed unit (M2.4.59):

- [x] Add opt-in observer restart probe to `soak.sh` and `soak.ps1`.
- [x] Emit `soak: RESTART` evidence with old/new observer PID/RPC and pre/post hub/observer heights after catch-up.
- [x] Wait for follower P2P dial logs before failing early soak iterations.
- [x] Update `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and operator soak guidance.
- [x] Regenerate `CODEBASE_STATS.md`, run local CI mirror, push, and check GitHub CI.

Next Agent 1 task:

- [ ] Diagnose and harden public-devnet local-mesh liveness when the hub logs `mfnd_producer_slot_skip` and height stalls at genesis.

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

- [x] Add `release-schema-wheelhouse` and `release-schema-install-offline` helpers for Bash and PowerShell.
- [x] Document offline wheelhouse workflow in `OPERATORS.md` and mark the checklist item complete.
- [ ] Regenerate `CODEBASE_STATS.md`, run local CI mirror, commit, push, and check GitHub CI.

Next Agent 2 task:

- [ ] Wire wheelhouse artifacts into release-archive dry-run validation for air-gapped hosts.
