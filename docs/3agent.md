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
- Stabilize Windows duplex P2P session chunk fanout so the auto-fanout integration smoke no longer needs a Windows-only ignore; Agent 3's participant smoke currently covers Windows permanence end-to-end.

## Agent 2: RPC, Security, Operations, Observability, CI

Current:

- Keep release-candidate evidence, RPC safety posture, CI mirror, support bundles, and operator runbooks launch-ready.

Done:

- RPC method classification, API-key enforcement for write/admin methods, request limits, connection caps, sanitized logs, release evidence schema, sign-off bundle checks, and launch go/no-go guidance.

Next:

- Add release archive assembly dry-run guidance or helper that stages public artifacts without secrets.
- Review any new participant smoke/nightly harness before it enters CI so it does not hide flaky infrastructure failures.

## Agent 3: Wallet, Storage, Faucet/Test Funding, Onboarding, Recovery, Permanence UX

Current:

- Harden archived participant rehearsal evidence gates while live rehearsal/nightly promotion remains blocked by mesh lifetime.

Done:

- Wallet/upload retrieval UX, HTTP/P2P restore, permanence demo helpers, funding helpers, seed restore, preflight/stop helpers, backup guidance, `wallet backup-info`, support bundles, recovery plans, recovery walkthrough helpers, and the first full participant rehearsal.
- Public-devnet rehearsal liveness and first-run decoy work is implemented, including slot advancement, synthetic genesis decoys, retrying transient funding/list RPC failures, avoiding dialable-peer pollution from inbound ephemeral source ports, non-mutating proposal mempool selection, wider pending-proposal rebroadcast windows, and robust PowerShell stream/token capture.
- A clean Windows `participant-rehearsal-smoke.ps1` run passed end-to-end with wallet funding, upload discovery, HTTP restore, SHA-256 verification, proof submission, and support-bundle capture.
- `permanence-demo.ps1` / `permanence-demo.sh` now fail fast with recorded local-mesh PID status and log paths when upload-list polling sees RPC connection-refused errors after the helper mesh dies.
- Participant rehearsal plan mode now tells operators the next real-run action and the expected `support_bundle=<dir>` success output; `docs/TESTNET.md` and `OPERATORS.md` now define the final PASS line/support bundle as participant proof-of-success evidence.
- `release-audit-packet.ps1` / `release-audit-packet.sh` can now ingest archived participant rehearsal transcripts and support-bundle manifests, validating the PASS line, restored SHA-256 shape, read-only bundle, matching commitment, and core node/upload/proof captures.
- Archived participant rehearsal evidence now binds the transcript's `support_bundle` reference to the provided bundle directory, with CI coverage proving mismatched evidence is rejected.

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

- Agent 3 hardened offline participant rehearsal evidence ingestion in release audit packets. Operators can now pass an archived rehearsal transcript plus support bundle; the audit packet validates the PASS line, restored SHA-256 shape, transcript-to-bundle match, read-only manifest, matching commitment, and required node/upload/proof captures without rerunning the flaky live smoke. Nightly promotion remains blocked pending the daemon-lifetime fix.
