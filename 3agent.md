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
| Agent 1 | Core protocol, consensus, networking, sync | Windows duplex P2P session chunk fanout runs the full auto-fanout smoke. | In progress in clean Agent 1 worktree. | Add restart/sync soak evidence for observer lag and delayed catch-up under node kill/restart. |
| Agent 2 | Security, RPC, operations, observability, release readiness, documentation truth | Pinned Draft 2020-12 release schema validation. | Completed locally; local CI mirror passed. | Hash-pin Python release-tool dependencies before treating third-party validation as reproducible release evidence. |
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
- Agent 1: Recent `main` commits landed outbound P2P connect bounds, boot peer list capping, boot cap startup log coverage, boot-dial connect quarantine without durable peer deletion, saved-peer reconnect quarantine before cap accounting, committee catch-up quarantine before cap accounting, gap-triggered recovery cap accounting, stable gap recovery peer-scoring labels, gap recovery success clearing transient peer penalties, and durable gap recovery peer retention.
- Agent 2: Release audit packet schema/sample artifacts are published for dashboards and independent validator tooling.
- Agent 2: Release audit packet schema now includes participant rehearsal evidence paths, and CI validates generated packets with participant evidence.
- Agent 2: Release artifacts now have pinned `jsonschema==4.17.3` Draft 2020-12 validation wrappers in local and GitHub CI.
- Agent 3: Recent `main` commits landed participant rehearsal smoke and faucet reward wait hardening.

## Agent 1 Detailed Plan

Current task:

- [x] Remove the Windows-only ignore from `chunk_p2p_auto_fanout_smoke`.
- [x] Add deterministic `mfn-net::block_sync` coverage that post-handshake chunk bursts are consumed through `GossipEndV1`.
- [x] Update `docs/TESTNET_CHECKLIST.md`, `docs/ROADMAP.md`, `docs/TESTNET.md`, and operator smoke references.
- [x] Regenerate `CODEBASE_STATS.md`, run targeted tests, and run local CI mirror.

Next Agent 1 task:

- [ ] Add restart/sync soak evidence for observer lag and delayed catch-up under node kill/restart.

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

- [x] Add pinned `scripts/public-devnet-v1/requirements-release-schema.txt` with `jsonschema==4.17.3`.
- [x] Add strict Draft 2020-12 validator wrappers for PowerShell and Bash release workflows.
- [x] Make local and GitHub CI run strict validation on published samples, generated audit packets, and a negative audit-packet fixture.
- [x] Update release docs and checklists.
- [x] Regenerate `CODEBASE_STATS.md` and run local CI mirror.
- [ ] Commit, push, and check GitHub CI.

Next Agent 2 task:

- [ ] Hash-pin Python release-tool dependencies before treating third-party validation as reproducible release evidence.
