# Three-Agent Coordination Checklist

This file coordinates the three Permawrite build lanes. Keep it current alongside
`docs/TESTNET_CHECKLIST.md`; the checklist tracks milestone completion, while this
file tracks who is actively doing what, what is done, and what should happen next.

## Operating Rules

- Pull latest `main` before starting new work when the tree is safe to update.
- Do not overwrite another agent's uncommitted work.
- Keep changes scoped to the active lane unless a cross-lane blocker prevents progress.
- Update this file whenever an agent starts a unit, ships it, discovers a blocker, or hands off work.
- Before pushing `main`, run the local CI mirror and then inspect GitHub CI.

## Agent 1: Core Protocol, Consensus, Networking, Sync

Current:

- Watch public-devnet liveness risks exposed by Agent 3 rehearsal runs.
- Own any consensus/P2P fixes that affect peer persistence, catch-up, proposal/vote flow, or block production.

Done:

- Sequential P2P block-sync catch-up, block-log replay, peer quarantine/scoring, bounded catch-up, self-dial skips, health liveness windows, and public-devnet P2P/session health checks.

Next:

- Add deterministic coverage for bounded outbound P2P dial retries under repeated unavailable seed lists.
- Review Agent 3's local-mesh evidence for any remaining P2P/process-lifetime issue before public-testnet invites.
- Add restart/sync soak evidence for observer lag and delayed catch-up under node kill/restart.

## Agent 2: RPC, Security, Operations, Observability, CI

Current:

- Add pinned Draft 2020-12 validation for release artifacts while preserving the offline dependency-free validator.

Done:

- RPC method classification, API-key enforcement for write/admin methods, request limits, connection caps, sanitized logs, release evidence schema, sign-off bundle checks, and launch go/no-go guidance.
- Release archive dry-run/validation, sign-off manifest validation, release JSON schema validation, final audit packet aggregation, authenticated exact-commit CI polling, and `release-audit-packet.v1` schema/sample publication are landed on `main` or staged in the current Agent 2 unit.
- `release-audit-packet.v1` schema now includes participant rehearsal evidence path fields, and CI validates generated audit packets with participant evidence.
- Pinned `jsonschema==4.17.3` Draft 2020-12 validator wrappers are staged for local and GitHub CI.

Next:

- Hash-pin Python release-tool dependencies before treating third-party validation as reproducible release evidence.
- Review any new participant smoke/nightly harness before it enters CI so it does not hide flaky infrastructure failures.

## Agent 3: Wallet, Storage, Faucet/Test Funding, Onboarding, Recovery, Permanence UX

Current:

- Improve release-audit handoff for participant rehearsal evidence while live rehearsal/nightly promotion remains blocked by mesh lifetime.

Done:

- Wallet/upload retrieval UX, HTTP/P2P restore, permanence demo helpers, funding helpers, seed restore, preflight/stop helpers, backup guidance, `wallet backup-info`, support bundles, recovery plans, recovery walkthrough helpers, and the first full participant rehearsal.
- Public-devnet rehearsal liveness and first-run decoy work is implemented, including slot advancement, synthetic genesis decoys, retrying transient funding/list RPC failures, avoiding dialable-peer pollution from inbound ephemeral source ports, non-mutating proposal mempool selection, wider pending-proposal rebroadcast windows, and robust PowerShell stream/token capture.
- A clean Windows `participant-rehearsal-smoke.ps1` run passed end-to-end with wallet funding, upload discovery, HTTP restore, SHA-256 verification, proof submission, and support-bundle capture.
- `permanence-demo.ps1` / `permanence-demo.sh` now fail fast with recorded local-mesh PID status and log paths when upload-list polling sees RPC connection-refused errors after the helper mesh dies.
- Participant rehearsal plan mode now tells operators the next real-run action and the expected `support_bundle=<dir>` success output; `docs/TESTNET.md` and `OPERATORS.md` now define the final PASS line/support bundle as participant proof-of-success evidence.
- `release-audit-packet.ps1` / `release-audit-packet.sh` can now ingest archived participant rehearsal transcripts and support-bundle manifests, validating the PASS line, restored SHA-256 shape, read-only bundle, matching commitment, and core node/upload/proof captures.
- Archived participant rehearsal evidence now binds the transcript's `support_bundle` reference to the provided bundle directory, with CI coverage proving mismatched evidence is rejected.
- `participant-rehearsal.ps1` / `participant-rehearsal.sh` now write a default evidence log containing the final PASS line and print `evidence_log=<file>` so release-audit packets can ingest the exact rehearsal proof without relying on manual terminal copy/paste.
- `participant-rehearsal.ps1` / `participant-rehearsal.sh` now accept `EvidenceDir` / `--evidence-dir` to co-locate `participant-rehearsal.log` and `support-bundle/` for release-audit packet ingestion, while preserving explicit path overrides.

Next:

- Continue participant UX audit of `docs/TESTNET.md` and `OPERATORS.md` from an outside-user perspective.
- Do not promote participant rehearsal smoke into nightly/ignored CI until the Windows daemon-lifetime blocker is fixed or the harness is scoped to a platform where it is proven stable.
- Add a public-devnet participant evidence fixture from a successful live rehearsal once the mesh runtime is stable enough to publish representative artifacts.
- Hand Agent 1 the current evidence: during a 5s-slot smoke, funding passed, height reached 3, upload-list polling continued for many successful RPC calls, then recorded hub/voters/observer exited without panic before the upload indexed.

## Cross-Agent Blockers

- Do not claim public-testnet readiness until the full local CI mirror is green and GitHub CI is green on `main`.
- Do not invite outside operators until a local participant rehearsal passes from a clean data root and the resulting logs/support bundle are reviewed.
- Public deterministic test validator seeds must be replaced before any shared, production-like, incentivized, or non-toy deployment.

## Latest Coordination Note

- Agent 1 promoted the M7.8 `chunk_p2p_auto_fanout_smoke` to run on Windows directly after a clean Windows ignored-smoke run and added deterministic post-handshake `ChunkV1` burst reader coverage.
- Agent 3 improved participant rehearsal release-audit handoff. Rehearsal helpers now accept `EvidenceDir` / `--evidence-dir` to co-locate the generated PASS evidence log and support bundle, so release audit packets can ingest both paths without manual terminal copy/paste or mismatched bundle selection. Nightly promotion remains blocked pending the daemon-lifetime fix.
