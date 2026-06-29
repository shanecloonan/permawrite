# Public Testnet Readiness Checklist

Permawrite is pre-audit experimental software. This checklist tracks the minimum operator, RPC, security, observability, and release hardening needed before any internet-facing public testnet.

## Agent 2: RPC, Security, Operations, Observability, CI

- [x] Classify JSON-RPC methods as `public-safe`, `wallet-write`, or `operator-admin` in `list_methods`.
- [x] Add optional RPC API-key enforcement for `wallet-write` and `operator-admin` methods.
- [x] Document RPC exposure risk, loopback-first operation, and firewall/TLS/API-key mitigations.
- [x] Document RPC DoS guards and remaining public-exposure risk in `SECURITY.md`.
- [x] Warn on every non-loopback RPC bind, including auth-enabled binds with public read methods.
- [x] Add live smoke coverage for auth-enabled non-loopback RPC bind warnings.
- [x] Add request body/line size limits to the TCP JSON-RPC server.
- [x] Add malformed JSON-RPC integration coverage for oversized request lines.
- [x] Add malformed JSON-RPC integration tests for partial and non-object requests.
- [x] Add per-connection read/write timeouts for the JSON-RPC TCP listener.
- [x] Add a bounded in-flight connection cap for accepted JSON-RPC clients.
- [x] Add `MFND_RPC_MAX_IN_FLIGHT` override and validation for the JSON-RPC connection cap.
- [x] Advertise RPC safety environment knobs in `mfnd` usage output.
- [x] Document RPC connection-cap tuning and `get_status` verification in the operator runbook.
- [x] Document RPC safety fields exposed by `mfn-cli status`.
- [x] Document `get_status` RPC bind metadata in CLI and operator guidance.
- [x] Report JSON-RPC connection-cap telemetry in machine-readable `get_status` diagnostics.
- [x] Report JSON-RPC listen address and public-bind state in machine-readable `get_status` diagnostics.
- [x] Report JSON-RPC request-line and I/O timeout limits in machine-readable `get_status` diagnostics.
- [x] Apply JSON-RPC write timeouts to overload/busy rejections before responding.
- [x] Add live coverage that slow JSON-RPC clients do not block later requests.
- [x] Read and validate JSON-RPC request lines before taking chain-state locks.
- [x] Log sanitized JSON-RPC request outcomes, including pre-dispatch rejections, without params or API keys.
- [x] Add operator-facing health/status diagnostics that are machine-readable and stable.
- [x] Add reverse-proxy TLS and firewall examples for Linux and Windows operators.
- [x] Add backup, upgrade, rollback, and key-rotation runbooks.
- [x] Confirm CI mirror catches fmt, clippy, tests, audit, and ignored/nightly smoke gaps before every push.
- [x] Add a public-testnet launch go/no-go checklist for release candidates and outside-operator invites.
- [x] Require `rpc.public_bind` / `rpc.listen_addr` verification in the launch go/no-go checklist.

## Agent 1 — Core Protocol, Consensus, Networking, Sync

- [x] Enforce sequential block-sync catch-up in `pull_blocks_to_tip`; stale, skipped, or out-of-order height progress now aborts with `NonSequentialHeight`.
- [x] Add multi-process restart catch-up coverage where a validator stops, falls behind by several blocks, restarts from disk, and catches up from saved peers.
- [x] Replay durable block-log suffixes on restart so default `redb` nodes advertise the persisted synced tip even without a fresh checkpoint.
- [x] Add adversarial fork/gap/stale rejection coverage for durable block-log replay and P2P block gossip.
- [x] Harden P2P outbound genesis mismatch handling with structured logs and no peer persistence on foreign chains.
- [x] Validate public-devnet manifest `seed_nodes` / `--p2p-dial` boot peers before dialing; trim, dedupe, and reject malformed `HOST:PORT` entries.
- [x] Skip boot/reconnect self-dials when a node's own P2P listen address appears in CLI dials, manifest seeds, or saved peers.
- [x] Cap `peers.json` reconnect fan-out so hand-edited or corrupted peer files cannot spawn unbounded boot dials.
- [x] Drop saved peers durably after outbound `genesis_mismatch` failures so foreign-chain peers are not retried after every restart.
- [x] Log saved-peer filtering at boot so malformed or duplicate `peers.json` entries are visible to operators.
- [x] Log saved-peer reconnect skips when a peer is already covered by CLI/manifest boot dials.
- [x] Log when saved-peer reconnect hits `max_outbound_peers` so cap-limited restarts are visible.
- [x] Bound periodic committee catch-up dials by `max_outbound_peers` and log cap-limited intervals.
- [x] Skip periodic committee catch-up self-dials when a node's own P2P listen address is present in saved peers.
- [x] Add deterministic unit coverage for committee catch-up self-skip before cap accounting.
- [x] Extend health checks to fail on stalled height over a configurable observation window, not just divergent tips.
- [x] Add a long-running local soak script for hub + voters + observer with periodic peer, tip, and sync assertions.
- [x] Harden peer scoring/quarantine for repeated handshake, decode, and sync-protocol violations.
- [x] Add peer-set level unit coverage proving quarantined peers are filtered from reconnect, catch-up, and fan-out snapshots until a later success clears the penalty.
- [x] Add deterministic unit coverage that peer quarantine expiry prunes penalties so transient failures do not permanently suppress a peer.
- [x] Pin the outbound handshake `genesis_mismatch expected=... got=...` failure label that drives durable foreign-peer cleanup.
- [x] Add block-sync unit coverage that catch-up aborts after too many interleaved non-`BlocksV1` frames instead of waiting forever.
- [x] Add block-sync unit coverage that large catch-up gaps request at most `MAX_BLOCKS_PER_GET_V1` blocks per round trip.
- [x] Add block-sync unit coverage that `BlocksV1` rejects advertised response counts above `MAX_BLOCKS_PER_GET_V1` before allocation/parsing.
- [x] Add block-sync unit coverage that `BlocksV1` encode refuses internal oversized response batches above `MAX_BLOCKS_PER_GET_V1`.

## Agent 3 — Wallet, Storage, Faucet/Test Funding, Onboarding

- [x] Add wallet-local upload retrieval UX so participants can export anchored payload bytes after `wallet upload`, HTTP/P2P backfill, or inbox assembly.
- [x] Extend P2P ChunkV1 smoke coverage to verify `uploads retrieve` after inbox assembly.
- [x] Add permanence-operator troubleshooting for bad RPC auth, missing chunks, failed proofs, and chain divergence.
- [x] Add a role-based "join the testnet" path for observers, wallet users, and storage operators.
- [x] Add public test-key replacement guidance before shared or incentivized deployments.
- [x] Extend HTTP backfill smoke coverage to verify `uploads retrieve` restores peer-replicated bytes.
- [x] Add one-step HTTP peer restore UX (`uploads fetch-http`) for replicated payload recovery.
- [x] Add public permanence demo script for upload, discover, HTTP restore, and proof submission.
- [x] Add public-devnet wallet funding helper for demo and participant onboarding.
- [x] Add wallet seed restore UX for test-only faucet and payout wallets.
- [x] Harden public-devnet funding helper to wait for recipient balance deltas on repeat runs.
- [x] Add Linux/macOS public-devnet wallet funding helper with balance-delta wait.
- [x] Add Linux/macOS public permanence demo script for upload, HTTP restore, and proof submission.
- [x] Add Windows public-devnet preflight diagnostics for required tools, helper runtimes, release binaries, and locked `mfnd` processes.
- [x] Add Linux/macOS public-devnet preflight diagnostics for required tools, helper runtimes, release binaries, and local mesh discovery.
- [x] Extend public-devnet preflight diagnostics to catch missing `wasm-pack` and `cargo-audit` before local CI mirror runs.
- [x] Add public-devnet toolchain recovery guidance for missing preflight and CI helper tools.
- [x] Add public-devnet stop helpers to release `mfnd` locks before rebuilds and CI.
- [x] Add participant wallet and upload-artifact backup guidance for funds, proving, and permanence restore.
- [x] Add `wallet backup-info` CLI inventory for wallet files, scan/light state, pending spends, and upload artifacts.
- [x] Extend `wallet backup-info` with artifact-root existence and payload-byte backup sizing.
- [x] Add JSON output mode to `wallet backup-info` for operator automation and seed-free support tickets.
- [x] Add upload-artifact payload-byte totals to `uploads local` and `uploads status` for backup sizing.
- [x] Add JSON output mode to `uploads local` and `uploads status` for backup automation and artifact reconciliation.
- [x] Add JSON output mode to `operator artifacts` for storage-operator backup manifests.
- [x] Add JSON output mode to `operator inbox-status` for chunk replication troubleshooting.
- [x] Add JSON output mode to `operator assemble-inbox` for scripted P2P artifact recovery.
- [x] Add JSON output mode to `operator backfill` for scripted HTTP artifact recovery.
- [x] Add JSON output mode to `uploads fetch-http` for scripted one-step HTTP restore.
- [x] Add JSON output mode to `wallet status` for stuck-wallet and sync-gap diagnostics.
- [x] Add JSON output mode to `wallet scan` and `wallet balance` for rescan support records.

## Cross-Agent Notes

- Do not claim public-testnet readiness until CI is green across rustfmt, clippy `-D warnings`, release tests, and cargo-audit.
- Any operator-facing behavior change must update `docs/TESTNET.md` or `scripts/public-devnet-v1/OPERATORS.md`.
