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

- Verify GitHub CI on `main` after bounded producer slot scan lands; then add integration smoke for hub height >= 1 within one slot duration.

Done:

- Sequential P2P block-sync catch-up, block-log replay, peer quarantine/scoring, bounded catch-up, self-dial skips, health liveness windows, public-devnet P2P/session health checks, Windows duplex P2P session chunk auto-fanout smoke, opt-in observer kill/restart evidence via `soak --restart-observer-once` / `-RestartObserverOnce` (`soak: RESTART`), and public-devnet validator-0 slot-1 ineligibility diagnosis (`public_devnet_validator0_needs_advancing_slots_for_liveness`).

Next:

- Add integration smoke that hub reaches height >= 1 within one slot duration after mesh start.
- Review Agent 3's local-mesh evidence for any remaining P2P/process-lifetime issue before public-testnet invites.

## Agent 2: RPC, Security, Operations, Observability, CI

Current:

- Continue cross-agent release gates; support Agent 1 mesh liveness blockers as needed.

Done:

- RPC method classification, API-key enforcement for write/admin methods, request limits, connection caps, sanitized logs, release evidence schema, sign-off bundle checks, and launch go/no-go guidance.
- Release archive dry-run/validation, sign-off manifest validation, release JSON schema validation, final audit packet aggregation, authenticated exact-commit CI polling, and `release-audit-packet.v1` schema/sample publication.
- Pinned `jsonschema==4.17.3` Draft 2020-12 validator wrappers in local and GitHub CI.
- Release-schema Python dependencies are hash-pinned and installed with `pip --require-hashes`.
- Offline wheelhouse/install helpers and operator guidance for air-gapped strict validation.
- Release-archive dry-run/validation now stages and requires hash-pinned release-schema wheelhouses for air-gapped hosts.
- Participant rehearsal smoke CI policy guard (`release-participant-smoke-policy-check`) keeps real-run mesh smokes out of default CI/nightly until mesh lifetime is stable.
- Release audit packets and archives now include participant smoke CI policy checks and staged policy helpers.

Next:

- Continue release-readiness gates from `docs/TESTNET_CHECKLIST.md`.
- Review any new participant smoke/nightly harness before it enters CI so it does not hide flaky infrastructure failures.

## Agent 3: Wallet, Storage, Faucet/Test Funding, Onboarding, Recovery, Permanence UX

Current:

- Improve release-audit handoff for participant rehearsal evidence while live rehearsal/nightly promotion remains blocked by mesh lifetime.

Done:

- Wallet/upload retrieval UX, HTTP/P2P restore, permanence demo helpers, funding helpers, seed restore, preflight/stop helpers, backup guidance, `wallet backup-info`, support bundles, recovery plans, recovery walkthrough helpers, and the first full participant rehearsal.
- Public-devnet rehearsal liveness and first-run decoy work is implemented.
- A clean Windows `participant-rehearsal-smoke.ps1` run passed end-to-end.
- `release-audit-packet` ingestion for participant rehearsal evidence is landed.

Next:

- Continue participant UX audit of `docs/TESTNET.md` and `OPERATORS.md` from an outside-user perspective.
- Do not promote participant rehearsal smoke into nightly/ignored CI until the Windows daemon-lifetime blocker is fixed or the harness is scoped to a platform where it is proven stable.
- Add a public-devnet participant evidence fixture from a successful live rehearsal once the mesh runtime is stable enough to publish representative artifacts.

## Cross-Agent Blockers

- Do not claim public-testnet readiness until the full local CI mirror is green and GitHub CI is green on `main`.
- Do not invite outside operators until a local participant rehearsal passes from a clean data root and the resulting logs/support bundle are reviewed.
- Public deterministic test validator seeds must be replaced before any shared, production-like, incentivized, or non-toy deployment.

## Latest Coordination Note

- Agent 1 added opt-in observer kill/restart evidence to public-devnet soak scripts (`soak: RESTART`).
- Agent 2 finished hash-pinned release-schema installs, offline wheelhouse helpers, release-archive wheelhouse staging/validation, and participant rehearsal smoke CI policy guard for air-gapped strict validation and flaky-mesh CI safety.
- Agent 3 improved participant rehearsal release-audit handoff with `EvidenceDir` / `--evidence-dir` co-location for audit packets.
