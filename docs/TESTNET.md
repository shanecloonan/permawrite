# Permawrite public devnet (M2.4)

This document describes how to run a **three-validator devnet** on loopback or LAN using the reference daemon `mfnd`. The chain is the same MFBN-1 consensus stack used in CI; privacy and permanence economics are live in consensus, while wallet-facing tooling remains library-only until M3.

**Security warning.** The validator seeds in [`mfn-node/testdata/public_devnet_v1.json`](../mfn-node/testdata/public_devnet_v1.json) are **public, deterministic test keys**. Never fund them on a network you care about. Follow the [test-key replacement runbook](../scripts/public-devnet-v1/OPERATORS.md#replacing-public-test-keys) before any shared, production-like, or incentivized deployment.

**RPC exposure warning.** Keep `--rpc-listen` on `127.0.0.1` unless you have an explicit firewall/TLS plan. If RPC must be reachable by wallets or operators, start `mfnd serve` with `--rpc-api-key <KEY>` or `MFND_RPC_API_KEY=<KEY>` and give clients the same key with `mfn-cli --rpc-api-key <KEY>` or `MFN_RPC_API_KEY=<KEY>`. The key gates `wallet-write` and `operator-admin` methods; public read methods remain open by design.

Read the [public-devnet threat model](PUBLIC_DEVNET_THREAT_MODEL.md) before advertising seed nodes, sharing RPC endpoints, or inviting outside operators. It separates controlled public devnet, internet-facing release-candidate gates, and future incentivized/adversarial readiness.

`mfnd serve` prints `mfnd_rpc_public_bind_warning` for every non-loopback RPC bind, including auth-enabled binds, because public read methods remain unauthenticated and the daemon does not terminate TLS.

`mfnd serve` accepts one newline-delimited JSON-RPC request per TCP connection, handles accepted RPC connections in bounded worker threads with a default cap of 64 in-flight connections (`MFND_RPC_MAX_IN_FLIGHT` overrides it), reports the configured cap, current in-flight count, request-line byte cap, I/O timeout, configured listen address, and whether the bind is public in `get_status`, applies 30s per-connection read/write timeouts to accepted workers and overload rejections, rejects request lines larger than 1 MiB before JSON parsing, reads/validates the request line before taking chain-state locks, logs sanitized RPC method/result/error-code/latency fields for dispatched and pre-dispatch rejected requests without params or API keys, and returns JSON-RPC errors for malformed partial JSON or non-object requests. These are devnet safety guards, not a substitute for firewalling, TLS termination, and upstream rate limits.

Concrete Linux/Windows firewall baselines, SSH forwarding, and TLS reverse-proxy examples are in the operator runbook: [`scripts/public-devnet-v1/OPERATORS.md#firewall-and-tls-examples`](../scripts/public-devnet-v1/OPERATORS.md#firewall-and-tls-examples).

---

## What you need

| Item | Notes |
|------|--------|
| Rust stable | Same toolchain as CI (`rust-toolchain.toml` in repo root). |
| `mfnd` binary | `cargo build -p mfn-node --release --bin mfnd` |
| Genesis file | `public_devnet_v1.json` (three equal-stake validators, quorum 2/3). |
| Chain identity | `genesis_id` **`7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df`** ([`public_devnet_v1.manifest.json`](../mfn-node/testdata/public_devnet_v1.manifest.json)). |
| Open TCP ports | One RPC + one P2P port per node (defaults bind `127.0.0.1:0` — OS assigns). |

On `mfnd serve`, stdout includes `mfnd_chain_network=public_devnet_v1` and `mfnd_chain_genesis_id=…` when `--genesis` points at the public spec. Peers reject handshakes when `genesis_id` differs.

---

## One-command local mesh (M2.4.3 / M2.4.9)

After `cargo build -p mfn-node --release --bin mfnd`:

| Platform | Start hub + voters + observer | Health check |
|----------|-------------------------------|--------------|
| Linux / macOS | `bash scripts/public-devnet-v1/start-all.sh` | `bash scripts/public-devnet-v1/health-check.sh` |
| Windows | `powershell -File scripts/public-devnet-v1/start-all.ps1` | `powershell -File scripts/public-devnet-v1/health-check.ps1` (exits 1 if tips diverge) |

`start-all` also launches a fourth **observer** (`serve` only, no validator seeds) that dials the hub P2P address. `health-check` compares the observer `get_tip` to the hub when `OBSERVER_RPC` is present in `devnet-ports.env`.

For a liveness window instead of a one-shot convergence check, set `MFN_HEALTH_STALL_SAMPLES=2` or higher before running `health-check`. The scripts wait `MFN_HEALTH_STALL_INTERVAL_SECONDS` between samples (default `30`) and require the shared hub tip to advance by at least `MFN_HEALTH_MIN_HEIGHT_DELTA` blocks (default `1`).

For a longer local soak, run `bash scripts/public-devnet-v1/soak.sh --duration-minutes 60` or `powershell -File scripts/public-devnet-v1/soak.ps1 -DurationMinutes 60`. The soak script starts the hub, two voters, and observer by default, checks that their recorded PIDs stay alive, asserts the follower/observer P2P dial logs, and repeatedly runs the multi-sample health check. Pass `--no-start` / `-NoStart` to attach to an already running mesh. Archive the final `soak: SUMMARY` line and every `soak: SAMPLE` line for release-candidate evidence; they record elapsed duration, iteration count, final sampled height/tip, genesis id, and per-role P2P peer/session counts.

Operator onboarding and seed-node list: [`scripts/public-devnet-v1/OPERATORS.md`](../scripts/public-devnet-v1/OPERATORS.md). **Storage permanence** (upload, chunk HTTP/P2P replication, SPoRA prove): see the [Permanence operators (M6 / M7)](../scripts/public-devnet-v1/OPERATORS.md#permanence-operators-storage--spora--m6--m7) and [Permanence troubleshooting](../scripts/public-devnet-v1/OPERATORS.md#permanence-troubleshooting) sections in that file.

Before publishing seed nodes or inviting outside operators, complete the [launch go/no-go checklist](../scripts/public-devnet-v1/OPERATORS.md#launch-gono-go-checklist). Treat any unchecked critical item as a launch blocker.

For release candidates, generate an evidence record with [`release-evidence.sh`](../scripts/public-devnet-v1/release-evidence.sh) or [`release-evidence.ps1`](../scripts/public-devnet-v1/release-evidence.ps1) and attach it to launch notes. Use `--json` / `-Json` when archiving the same evidence for CI dashboards or automation. JSON output carries `schema_version=release-evidence.v1`; the schema is [`release-evidence-v1.schema.json`](release-evidence-v1.schema.json), with a sample artifact in [`release-evidence-v1.sample.json`](release-evidence-v1.sample.json). The generated record captures the commit, dirty-tree state, `CODEBASE_STATS.md` timestamp, CI status when available, optional health-check output, optional RPC posture, and operator sign-off fields; unknown fields still require manual review. Before launch, complete the [release sign-off bundle review](../scripts/public-devnet-v1/OPERATORS.md#release-sign-off-bundle-review), fill out the [artifact inventory template](RELEASE_ARTIFACT_INVENTORY_TEMPLATE.md), and publish artifacts using the archive layout in that template.

Operational recovery: before joining a shared network, read the [backup, upgrade, rollback, and key-rotation runbook](../scripts/public-devnet-v1/OPERATORS.md#backups-upgrades-rollback-and-key-rotation). Current devnet validator keys are genesis-bound test keys; there is no live hot-swap for validator VRF/BLS seeds on an already-published genesis.

---

## Join The Testnet

Pick the lightest role that matches what you want to test:

| Role | Start here | You should be able to |
|------|------------|-----------------------|
| Observer | Run `start-all` locally or start `mfnd serve` with no validator env | Verify the public `genesis_id`, follow tips, query RPC, and report divergence. |
| Wallet user | Connect `mfn-cli --rpc <RPC>` to a synced node | Create a wallet, scan/balance, upload data, publish claims, and retrieve local artifacts. |
| Storage operator | Run a synced node plus `mfn-storage-operator` / `mfn-cli operator ...` | Replicate chunks, assemble artifacts, submit SPoRA proofs, and restore payload bytes. |
| Validator candidate | Follow the operator invite list and [replace every public test seed](../scripts/public-devnet-v1/OPERATORS.md#replacing-public-test-keys) before real deployments | Produce or vote on devnet blocks while keeping RPC private and P2P reachable. |

Minimal participant path:

1. Run a preflight: `powershell -File scripts/public-devnet-v1/preflight.ps1` on Windows or `bash scripts/public-devnet-v1/preflight.sh` on Linux/macOS. Use `-Strict` / `--strict` before CI or push preparation.
2. Build release binaries: `cargo build -p mfn-node --release --bin mfnd`, `cargo build -p mfn-cli --release --bin mfn-cli`, and for storage operators `cargo build -p mfn-storage-operator --release --bin mfn-storage-operator`.
3. Start or connect to a node whose stdout `mfnd_chain_genesis_id=` equals `7fef4492dba32d7ba652cceb5465cae86d6630a9e0a4855adf3acdc5f6b2a2df`.
4. Keep RPC on loopback or behind a tunnel. If the node uses `--rpc-api-key`, pass `mfn-cli --rpc-api-key <KEY>` or set `MFN_RPC_API_KEY=<KEY>`.
5. Run `mfn-cli --rpc <RPC> status` for a machine-readable node snapshot, then `mfn-cli --rpc <RPC> tip` and confirm `tip_height` advances or matches the mesh health check. If a wallet looks stale, run `mfn-cli --rpc <RPC> --wallet ./alice.json wallet status --json` and compare `scan_height`, `tip_height`, `blocks_behind`, and `sync_needed` before rescanning; use `wallet scan --json` or `wallet balance --json` when you need a seed-free support record of the rescan result.
6. Create a test wallet with `mfn-cli --wallet ./alice.json wallet new`, or restore a known test-only seed with `mfn-cli --wallet ./alice.json wallet restore <SEED_HEX>`. Back up the wallet file and never reuse devnet keys for real funds.
7. Fund the wallet from an operator-controlled devnet faucet wallet, for example `powershell -File scripts/public-devnet-v1/fund-wallet.ps1 -PlanOnly` or `bash scripts/public-devnet-v1/fund-wallet.sh --plan-only`, then rerun with a faucet wallet and `./alice.json` as the recipient.
8. For permanence testing, upload with `wallet upload --json`, capture `storage_commitment_hash` and `upload_artifact_dir`, replicate with `operator push-chunks` or `operator backfill`, verify with `uploads retrieve`, and prove with `operator prove`.
9. Before inviting outside users, run a local real-run rehearsal smoke with `powershell -File scripts/public-devnet-v1/participant-rehearsal-smoke.ps1 -PlanOnly` or `bash scripts/public-devnet-v1/participant-rehearsal-smoke.sh --plan-only`, then rerun without plan mode. The smoke starts the local producer mesh, restores/checks the validator-0 test-only faucet wallet by default, refuses to overwrite a custom faucet wallet, waits for the faucet to scan a spendable reward, runs the participant rehearsal, and stops the mesh. For an already-running public devnet with an operator-controlled faucet, run `participant-rehearsal.ps1` / `participant-rehearsal.sh` directly; it funds the uploader wallet, uploads, restores over HTTP, verifies SHA-256, proves, and captures a support bundle. If the wallet is already funded and you only need the permanence loop, use `permanence-demo.ps1` / `permanence-demo.sh`.
10. If anything stalls, use the [Permanence troubleshooting](../scripts/public-devnet-v1/OPERATORS.md#permanence-troubleshooting) matrix before deleting data dirs or regenerating wallets. For support tickets, collect a read-only bundle with `powershell -File scripts/public-devnet-v1/support-bundle.ps1 -PlanOnly` or `bash scripts/public-devnet-v1/support-bundle.sh --plan-only`, then rerun with `--rpc`/`-Rpc`, wallet, commitment, optional peer, optional data-dir identifiers, and `--release-evidence` / `-ReleaseEvidence` for launch sign-off bundles. Before mutating artifacts, print a recovery plan with `powershell -File scripts/public-devnet-v1/recovery-plan.ps1` or `bash scripts/public-devnet-v1/recovery-plan.sh`; for a guided support-bundle -> plan -> restore -> hash-check flow, use `recovery-walkthrough.ps1` or `recovery-walkthrough.sh`.

Before rebuilding release binaries or running CI after a local mesh, stop recorded devnet PIDs with `powershell -File scripts/public-devnet-v1/stop-all.ps1 -DryRun` then `powershell -File scripts/public-devnet-v1/stop-all.ps1`, or `bash scripts/public-devnet-v1/stop-all.sh --dry-run` then `bash scripts/public-devnet-v1/stop-all.sh`. Use `-AllMfnd` / `--all-mfnd` only when stale `mfnd` processes still hold release binaries.

Wallet recovery and permanence recovery are separate. The wallet JSON contains the seed and scan/light-client state needed for funds, while uploaded payload artifacts live under `{wallet_stem}.upload-artifacts/`. Run `mfn-cli --wallet ./alice.json wallet backup-info` (or add `--json` for automation), then back up both the wallet file and any reported artifact directory before deleting a machine or data directory. Use `operator artifacts --json` / `uploads local --json` and `uploads status --json` when a backup script or support ticket needs a structured artifact manifest; use `uploads fetch-http --json`, `operator backfill --json`, `operator inbox-status --json`, and `operator assemble-inbox --json` when diagnosing or rebuilding replicated chunks before proving. `support-bundle.ps1` / `support-bundle.sh` collects these read-only JSON diagnostics into one directory for handoff without exposing seeds. If only the wallet seed survives, rescan funds from the chain, then rebuild missing artifacts from honest peers with HTTP or P2P inbox assembly before proving or retrieving payload bytes.

---

## Network roles

| Role | Flags | Responsibility |
|------|--------|----------------|
| **Hub producer** | `serve --produce` | Slot timer, builds proposals when VRF-eligible, seals when local validator is proposer and quorum votes arrive. |
| **Committee voter** | `serve --committee-vote` | Votes on inbound proposals; periodic catch-up dials to saved peers; does **not** run the slot loop. |
| **Observer** | `serve` (no produce flags) | Syncs blocks/txs, exposes JSON-RPC; no validator env required. |

CI uses one hub + two committee voters so only the proposer seals (avoids forked tips under `expected_proposers_per_slot: 10` in the local harness spec). The hub does **not** run the committee catch-up dial loop (**M2.3.29**); voters do. Proposal fan-out reads committee `VoteV1` replies on both fresh dials and registered sessions (**M2.3.30**). Inbound P2P blocks must be exactly `tip_height + 1` (**M2.3.31**); stale or gap frames reject before `apply` (catch-up aborts stay clean). The **public devnet** spec sets `expected_proposers_per_slot: 1.5` so operators can later run three `--produce` nodes with natural slot skipping; the commands below match the proven hub + voter topology.

---

## Environment (per validator)

Set these in the shell that starts each `mfnd serve` process:

```text
MFND_VALIDATOR_INDEX=0   # 0, 1, or 2 — must match genesis row
MFND_VRF_SEED_HEX=<32-byte hex from genesis validators[].vrf_seed_hex>
MFND_BLS_SEED_HEX=<32-byte hex from genesis validators[].bls_seed_hex>
```

Seeds for `public_devnet_v1.json` are listed in that file. Index `0` is the usual hub producer.

---

## Example: three nodes on one machine

Build once:

```bash
cargo build -p mfn-node --release --bin mfnd
export MFND=target/release/mfnd
export GENESIS=mfn-node/testdata/public_devnet_v1.json
```

**Validator 0 (hub)** — note RPC/P2P lines on stdout:

```bash
mkdir -p /tmp/mfn-v0
MFND_VALIDATOR_INDEX=0 \
MFND_VRF_SEED_HEX=0101010101010101010101010101010101010101010101010101010101010101 \
MFND_BLS_SEED_HEX=6565656565656565656565656565656565656565656565656565656565656565 \
$MFND --data-dir /tmp/mfn-v0 --genesis $GENESIS --store fs \
  --rpc-listen 127.0.0.1:0 --p2p-listen 127.0.0.1:0 \
  --slot-duration-ms 30000 serve --produce
```

Copy `mfnd_p2p_listening=HOST:PORT` from stdout as `HUB_P2P`.

**Validator 1 (committee voter):**

```bash
mkdir -p /tmp/mfn-v1
MFND_VALIDATOR_INDEX=1 \
MFND_VRF_SEED_HEX=0202020202020202020202020202020202020202020202020202020202020202 \
MFND_BLS_SEED_HEX=7676767676767676767676767676767676767676767676767676767676767676 \
$MFND --data-dir /tmp/mfn-v1 --genesis $GENESIS --store fs \
  --rpc-listen 127.0.0.1:0 --p2p-listen 127.0.0.1:0 \
  --p2p-dial $HUB_P2P --slot-duration-ms 30000 serve --committee-vote
```

**Validator 2** — same as validator 1 with index `2` and the third seed pair from genesis; add `--p2p-dial $HUB_P2P`.

---

## Health checks (JSON-RPC)

Each node prints `mfnd_serve_listening=127.0.0.1:PORT`.

**M3.0 / M3.1 — `mfn-cli`** (after `cargo build -p mfn-cli --release`):

```bash
mfn-cli --rpc 127.0.0.1:<RPC_PORT> tip
mfn-cli --rpc 127.0.0.1:<RPC_PORT> methods

# If the node was started with --rpc-api-key / MFND_RPC_API_KEY:
mfn-cli --rpc 127.0.0.1:<RPC_PORT> --rpc-api-key <KEY> mempool

# Wallet (local wallet.json; scans blocks via get_block)
mfn-cli wallet new
mfn-cli --rpc 127.0.0.1:<RPC_PORT> wallet balance --json

# Send (then stop serve and `mfnd step` to mine the mempool tx)
mfn-cli --rpc 127.0.0.1:<RPC_PORT> wallet send <VIEW_HEX> <SPEND_HEX> <AMOUNT> --fee 10000 --json

# Upload bytes (permanence anchor; default replication 3)
mfn-cli --rpc 127.0.0.1:<RPC_PORT> wallet upload ./myfile.bin --replication 3 --json
mfn-cli --rpc 127.0.0.1:<RPC_PORT> uploads list --include-claims --json

# Upload + bind authorship to commitment (same tx)
mfn-cli --rpc 127.0.0.1:<RPC_PORT> wallet upload ./myfile.bin --message "attribution" --json

# Authorship claim over a data root (discover via get_claims_for after mining)
mfn-cli --rpc 127.0.0.1:<RPC_PORT> wallet claim <DATA_ROOT_HEX> --message "attribution" --json
mfn-cli --rpc 127.0.0.1:<RPC_PORT> claims for <DATA_ROOT_HEX> --json

# Cached balance vs tip (no block download)
mfn-cli --rpc 127.0.0.1:<RPC_PORT> wallet status --json

# Export anchored bytes from a wallet-local artifact after upload/backfill/assembly
mfn-cli --wallet ./wallet.json uploads retrieve <COMMIT_HASH_HEX> ./restored.bin

# Restore from an HTTP chunk peer in one step (backfill + retrieve)
mfn-cli --rpc 127.0.0.1:<RPC_PORT> --wallet ./wallet.json \
  uploads fetch-http <COMMIT_HASH_HEX> ./restored.bin 127.0.0.1:18780 --json
mfn-cli --rpc 127.0.0.1:<RPC_PORT> --wallet ./wallet.json \
  operator fetch-chunk <COMMIT_HASH_HEX> 0 127.0.0.1:18780 --json
mfn-cli --rpc 127.0.0.1:<RPC_PORT> --wallet ./wallet.json \
  operator push-chunks <COMMIT_HASH_HEX> <PEER_P2P> --json
mfn-storage-operator push-chunks --wallet ./wallet.json <COMMIT_HASH_HEX> <PEER_P2P> --json

# Storage proof diagnostics
mfn-cli --rpc 127.0.0.1:<RPC_PORT> operator challenge <COMMIT_HASH_HEX> --json
mfn-cli --rpc 127.0.0.1:<RPC_PORT> --wallet ./wallet.json operator prove <COMMIT_HASH_HEX> --json
mfn-cli --rpc 127.0.0.1:<RPC_PORT> operator pool --json
```

Raw one-liner (no CLI):

```bash
echo '{"jsonrpc":"2.0","method":"get_tip","id":1}' | nc 127.0.0.1 <RPC_PORT>
```

All validators should report the same `tip_height` and `tip_id` after a slot seals. Use `get_block_header` with `"height": N` to inspect canonical block ids. To detect a stalled local mesh, run `health-check` with `MFN_HEALTH_STALL_SAMPLES=2` and an interval longer than the configured slot duration.

---

## P2P mesh tips

- **Boot dial:** At least one `--p2p-dial` to a peer already on the chain (usually the hub). Repeat `--p2p-dial` for multiple seeds (**M2.4.4**).
- **Manifest seeds:** With `--genesis path/to/public_devnet_v1.json`, `mfnd` also merges `seed_nodes` from the sibling `public_devnet_v1.manifest.json` with explicit CLI dials (trimmed, deduped, and validated as `HOST:PORT` before dialing). Operators append public `host:port` values to that list; stdout prints `mfnd_p2p_boot_dials=…` when any boot peer is configured. The merged list is capped at 64 peers, preserving explicit `--p2p-dial` entries before manifest seeds; oversized lists log `mfnd_p2p_boot_dials_capped configured=... retained=... dropped=... cap=64`.
- **Self-dial skip:** If the node's own resolved P2P listen address appears in CLI dials, manifest seeds, or saved peers, `mfnd` skips that outbound connection and logs `mfnd_p2p_self_dial_skip peer=...`.
- **Stale/unavailable seeds:** Outbound P2P boot, saved-peer reconnect, and catch-up dials bound each resolved TCP connect attempt to 5s before trying the next resolved address or logging `mfnd_p2p_dial_abort` / `mfnd_p2p_catchup_dial_abort`. Treat repeated aborts for public seeds as stale seed inventory, firewall, or reachability issues rather than consensus failures.
- **Persistent peers:** Successful handshakes append to `peers.json` under `--data-dir`; restart reconnects automatically (**M2.3.22**, **M2.4.2** block-sync on reconnect). Saved-peer reconnect skips addresses already dialed at boot and logs `mfnd_p2p_reconnect_skip peer=... reason=boot_dial`; it also skips the node's own P2P listen address. `max_outbound_peers` defaults to 8 and is clamped to a hard maximum of 64 on load/save so a bad peer file cannot cause an unbounded reconnect storm; if the cap stops additional reconnects, `mfnd` logs `mfnd_p2p_reconnect_cap_reached count=... cap=...`. Malformed, empty, or duplicate saved peers are filtered on load; `mfnd` logs `mfnd_peers_load_filtered raw=... kept=... filtered=...` when that happens.
- **Genesis mismatch:** Outbound dials to peers on a foreign genesis fail before peer persistence and log `mfnd_p2p_dial_abort peer=... reason=genesis_mismatch expected=... got=...`. If that peer was already saved, `mfnd` also removes it from `peers.json` and logs `mfnd_p2p_peer_drop peer=... reason=genesis_mismatch ...`. Treat this as a seed-list or manifest mismatch, not a transient network failure.
- **Catch-up:** Outbound dials pull missing blocks when the remote tip is ahead; handshake height uses the live chain tip (**M2.3.24+**). Periodic committee catch-up uses the same available peer set, skips the node's own P2P listen address, and honors `max_outbound_peers`; self-skips log `mfnd_p2p_self_dial_skip peer=...`, and capped intervals log `mfnd_p2p_catchup_cap_reached count=... cap=...`.
- **Restart replay:** `mfnd serve`, `mfnd status`, `mfnd save`, and solo `mfnd step` load the latest checkpoint/genesis and replay any durable block-log suffix before advertising a tip. This keeps default `redb` nodes restart-safe after P2P sync even when no fresh checkpoint has been saved yet.
- **Peer quarantine:** Repeated outbound dial, fan-out, or catch-up failures temporarily quarantine a peer in memory; while quarantined, reconnect, committee catch-up, gap catch-up, and fan-out skip that address. Successful handshakes or pushes clear the penalty. Operators can watch for `mfnd_p2p_peer_quarantine peer=...` in logs.

---

## CI reference

Integration coverage lives in:

- `mfn-cli/tests/chunk_p2p_auto_fanout_smoke.rs` — solo hub `--produce` + **M7.5** session chunk fan-out (**M7.8**).
- `mfn-cli/tests/chunk_p2p_three_validator_produce_smoke.rs` — three-validator hub upload + manual `push-chunks` (**M7.7**) or auto fan-out (**M7.9**, `--ignored`).
- `mfn-node/tests/three_validator_produce_smoke.rs` — three-process harness, hub + two voters, shared tip through **height 2** (**M2.3.25**).
- `mfn-node/tests/three_validator_all_produce_smoke.rs` — three `--produce` validators on `devnet_three_validators_produce.json` (`expected_proposers_per_slot: 1.5`), shared canonical tip (**M2.3.26**).
- `mfn-node/tests/mfnd_smoke.rs::mfnd_p2p_restart_reconnect_catches_up_from_saved_peer` — ignored restart safety smoke: saved peer reconnect catches up from disk after missing blocks.
- `mfn-node/tests/mfnd_smoke.rs::mfnd_serve_replays_redb_block_log_without_checkpoint` — default-store restart replay smoke: `serve` reconstructs the synced tip from `redb` block logs without a fresh checkpoint.
- `mfn-node/tests/mfnd_smoke.rs::mfnd_serve_p2p_dial_rejects_foreign_genesis_and_does_not_save_peer` — outbound mismatch smoke: foreign-genesis peers produce structured abort logs and are not written to `peers.json`.
- `mfn-rpc::dispatch` unit tests — `get_status` exposes public-safe P2P health fields (`configured`, `listen_addr`, `peer_count`, `session_count`, `max_outbound_peers`) for operator checks.
- `scripts/public-devnet-v1/health-check.{sh,ps1}` syntax checks — default public-devnet health requires hub, both voters, and observer RPC endpoints to be discoverable; set `MFN_HEALTH_REQUIRE_ALL_ROLES=0` only for intentional partial-mesh diagnostics.
- `.github/workflows/ci.yml::public-devnet scripts` plus `scripts/ci-check.{sh,ps1}` — parse-check Bash and PowerShell public-devnet helpers, assert recovery walkthrough and participant rehearsal plan modes, and smoke-check release-evidence Markdown/JSON output before operator-script regressions can land.
- `mfn-net::serve` unit tests — pin the outbound `genesis_mismatch expected=... got=...` failure-label contract used by `mfnd` to remove durable foreign peers, plus stable block-sync abort labels used for transient peer scoring/quarantine.
- `mfn-net::handshake` unit tests — outbound TCP connect attempts are bounded by `P2P_CONNECT_TIMEOUT`, try later resolved addresses after an unavailable first address, and reject empty address resolutions deterministically.
- `mfn-net::block_sync` unit tests — sequential catch-up, skipped-height rejection, large-gap request capping, no-progress empty-response rejection, exact response-size rejection before apply, response-count encode/decode capping, interleaved production/gossip frame skipping, bounded abort after too many non-`BlocksV1` frames, and unsolicited post-handshake `BlocksV1` batch contiguity checks.
- `mfn-net::light_follow` unit tests — light-follow P2P response row-count encode/decode caps plus bounded interleaved production/gossip frame skipping before `LightFollowV1` replies.
- `mfn-node::p2p_light_follow_fetch` unit tests — outbound P2P light-follow rejects responses with more rows than requested or non-contiguous row heights before JSON/quorum use, and long JSON page ranges are capped to the wire request window.
- `mfn-net::serve` unit tests — gap-triggered catch-up peer selection skips the node's own P2P listen address before spawning recovery dials.
- `mfn-node::p2p_block_sync` unit tests — block-sync and light-follow provider responses stop at the largest prefix that fits `MAX_FRAME_PAYLOAD_LEN`.
- `mfn-node::mfnd_cli` / `mfn-node::p2p_boot` / `mfn-node::p2p_fanout` unit tests — manifest/CLI boot-peer validation for malformed ports, whitespace, duplicate seeds, bracketed IPv6, oversized manifest capping with explicit-dial priority, capped-list startup log formatting, self-dial detection, boot-dial reconnect skip classification, reconnect cap classification, committee catch-up self-skip before cap accounting, peer-set quarantine filtering and expiry, and durable foreign-genesis `peers.json` cleanup.
- `mfn-store::peers_persist` unit tests — `peers.json` save/load sorting, malformed/duplicate peer filtering reports, and bounded reconnect fan-out caps.
- `mfn-store::replay` and `mfn-node::p2p_gossip` unit tests — adversarial replay/gossip coverage for forked prefixes, height gaps, stale blocks, and next-height fork rejection.
- `mfn-node/tests/multi_validator_producer.rs` — in-process proposal/vote/quorum.

Run locally:

```bash
# Required local tools: Rust/rustup, Node.js for CODEBASE_STATS.md,
# wasm-pack (`cargo install wasm-pack --locked`), cargo-audit
# (`cargo install cargo-audit --locked`), and on Windows the GNU binutils
# toolchain that provides dlltool.exe.
node scripts/codebase-stats.mjs

# Required before pushing to main; mirrors GitHub CI fmt, clippy, release tests,
# wasm, and cargo-audit gates.
bash scripts/ci-check.sh
powershell -File scripts/ci-check.ps1

# Slow ignored/nightly harnesses; run before public-devnet release candidates
# and after changes to consensus, P2P sync, production, light-client, or storage flows.
bash scripts/ci-ignored.sh
powershell -File scripts/ci-ignored.ps1

cargo test -p mfn-node --test three_validator_produce_smoke --release
cargo test -p mfn-node --test three_validator_all_produce_smoke --release
cargo test -p mfn-store replay --lib
cargo test -p mfn-store peers_persist --lib
cargo test -p mfn-node p2p_boot --lib
cargo test -p mfn-node p2p_fanout --lib
cargo test -p mfn-node p2p_gossip --lib
cargo test -p mfn-node --test mfnd_smoke mfnd_serve_p2p_dial_rejects_foreign_genesis_and_does_not_save_peer
cargo test -p mfn-node --test mfnd_smoke mfnd_serve_replays_redb_block_log_without_checkpoint --release
cargo test -p mfn-node mfnd_p2p_restart_reconnect_catches_up_from_saved_peer --release -- --ignored
cargo test -p mfn-cli --test light_scan_three_validator_smoke --release -- --ignored

# Operator soak (starts local public-devnet-v1 unless --no-start is supplied)
bash scripts/public-devnet-v1/soak.sh --duration-minutes 60

# Real-run participant rehearsal smoke against the local public-devnet helper mesh
bash scripts/public-devnet-v1/participant-rehearsal-smoke.sh --plan-only
```

---

## Roadmap

| Milestone | Focus |
|-----------|--------|
| **M2.4** (this doc) | Operator runbook + public devnet genesis. |
| **M3** | `mfn-cli` wallet (stealth scan, CLSAG send, storage upload). |
| **M4** | WASM bindings for browser wallets. |
| **M5+** | Hardening, audits, public incentivized testnet. |

Privacy (CLSAG, ring signatures, stealth addresses) and permanence (storage endowments, SPoRA proofs) are implemented in consensus and wallet **libraries**; the devnet exercises block production and P2P sync first, then wallets attach via JSON-RPC in M3.
