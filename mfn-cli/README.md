# `mfn-cli`

Operator CLI for Permawrite (**M3.0** / **M3.1**): talks to a running [`mfnd`](../mfn-node) node over newline-delimited JSON-RPC 2.0 and drives [`mfn-wallet`](../mfn-wallet) for local key material + chain scanning.


## Build

```bash
cargo build -p mfn-cli --release
```

## Usage

```bash
# Machine-readable node health/status snapshot
mfn-cli --rpc 127.0.0.1:18731 status

# Chain tip (same fields as mfnd get_tip RPC)
mfn-cli --rpc 127.0.0.1:18731 tip

# Discover server methods
mfn-cli methods

# Block header at height 1
mfn-cli block-header 1

# Mempool tx ids
mfn-cli mempool

# Arbitrary call (pretty-printed JSON result)
mfn-cli call get_tip
mfn-cli call get_block_header --params '{"height":1}'

# Wallet (writes wallet.json in cwd by default)
mfn-cli wallet new
mfn-cli --wallet ./restored.json wallet restore <SEED_HEX>
mfn-cli --wallet ./validator-faucet.json wallet restore <BLS_SEED_HEX> \
  --key-derivation payout_stealth_v1
mfn-cli wallet address
mfn-cli --wallet ./alice.json wallet scan --json
mfn-cli wallet light-scan
mfn-cli wallet balance --json
mfn-cli wallet status --json
mfn-cli --wallet ./alice.json wallet backup-info

# Send (CLSAG transfer + submit_tx; mine with `mfnd step` after stopping serve)
mfn-cli --rpc 127.0.0.1:<PORT> wallet send <VIEW_PUB_HEX> <SPEND_PUB_HEX> <AMOUNT> \
  --fee 10000 --ring-size 8

# Public-devnet helper: fund a participant wallet from an operator faucet wallet
powershell -File scripts/public-devnet-v1/preflight.ps1
bash scripts/public-devnet-v1/preflight.sh
powershell -File scripts/public-devnet-v1/fund-wallet.ps1 -PlanOnly
bash scripts/public-devnet-v1/fund-wallet.sh --plan-only

# Public-devnet permanence demo (upload -> HTTP restore -> prove)
powershell -File scripts/public-devnet-v1/permanence-demo.ps1 -PlanOnly
bash scripts/public-devnet-v1/permanence-demo.sh --plan-only

# Permanent storage upload (anchor to self; fee defaults to upload_min_fee + tip)
mfn-cli --rpc 127.0.0.1:<PORT> wallet upload ./document.bin --replication 3

# Upload with MFCL authorship claim bound to data_root + commitment hash
mfn-cli --rpc 127.0.0.1:<PORT> wallet upload ./document.bin --message "signed by me"

# Retrieve payload bytes from a wallet-local upload artifact
mfn-cli --wallet ./alice.json uploads retrieve <COMMITMENT_HASH_HEX> ./restored-document.bin

# One-step HTTP peer restore (backfill artifact + write restored bytes)
mfn-cli --rpc 127.0.0.1:<PORT> --wallet ./bob.json \
  uploads fetch-http <COMMITMENT_HASH_HEX> ./restored-document.bin 127.0.0.1:18780 --json

# Authorship claim (MFCL in tx.extra; unbound unless --commit-hash set)
mfn-cli --rpc 127.0.0.1:<PORT> wallet claim <DATA_ROOT_HEX> --message "hello permanence"
```

Default RPC address: `127.0.0.1:18731` (mfnd default `--rpc-listen`).

Authenticated testnet RPC: pass `--rpc-api-key KEY` or set `MFN_RPC_API_KEY=KEY` when the node was started with `mfnd serve --rpc-api-key KEY` / `MFND_RPC_API_KEY=KEY`. The key is attached to every JSON-RPC request and is required by nodes that gate `wallet-write` and `operator-admin` methods.

`mfn-cli status` prints the `get_status` snapshot. Operators should check `rpc.auth_enabled`, `rpc.listen_addr`, `rpc.public_bind`, `rpc.max_in_flight`, `rpc.current_in_flight`, `rpc.max_request_line_bytes`, and `rpc.io_timeout_ms` when validating public-devnet RPC exposure and capacity settings.

Default wallet file: `wallet.json` (override with `--wallet PATH`). The file stores a 32-byte `seed_hex`, key-derivation tag, pending spends, scan cache, and optional light-client checkpoint. **Back it up** — it is the only recovery path for funds.

`wallet restore SEED_HEX [--key-derivation mfn_wallet_v1|payout_stealth_v1]` writes a wallet file from a 32-byte seed. Use the default `mfn_wallet_v1` for normal user wallets. Use `payout_stealth_v1` only for validator payout/faucet test wallets whose rewards are derived from validator BLS seed material. Pass global `--force` to overwrite an existing wallet file.

Wallet backup is two-layered:

- `wallet.json` / `--wallet PATH`: required to recover spend authority, pending spends, and scan/light checkpoints.
- `{wallet_stem}.upload-artifacts/`: required to serve chunks, prove storage, and retrieve payload bytes without relying on a peer.

If you restore only the seed, funds can be rescanned from the chain, but local upload artifacts are not recreated. Use `uploads local` / `uploads status` to inventory artifacts before backup; add `--json` when scripting backups or support diagnostics. If artifacts are missing but peers still hold byte-identical chunks, rebuild them with `uploads fetch-http --json`, `operator backfill --json`, or P2P inbox assembly, then re-run `uploads retrieve`.

`wallet backup-info` prints a seed-free inventory for backup planning: wallet path/version, key derivation, scan/cache state, pending spends, light-checkpoint presence, upload artifact root/count/payload bytes, and whether artifact backup is needed. Add `--json` for automation or support tickets.

`wallet scan` / `wallet balance` fetch full blocks via `get_block` after the persisted `scan_height` when `owned_outputs` is populated (**M3.6**); otherwise they replay from height `1`. Add `--json` to either command for support-safe automation fields: `tip_height`, `blocks_scanned`, `utxo_cache`, `scan_height`, `balance`, `owned_count`, pending-spend count, and light-summary presence.

`wallet light-scan` (**M3.11**) verifies BLS headers and validator-set evolution via [`mfn-light`](../mfn-light) + batched `get_light_follow`, scans txs with `get_block_txs` only (no full block download), and persists `light_checkpoint_hex` in `wallet.json` for incremental resume.

```bash
# Require agreeing evolution batches from extra RPC nodes and/or P2P peers (**M3.12**)
mfn-cli --rpc 127.0.0.1:18731 wallet light-scan \
  --quorum-rpc 127.0.0.1:18732,127.0.0.1:18733 \
  --quorum-p2p 127.0.0.1:18740,127.0.0.1:18741
```

The primary `--rpc` node must expose P2P fetch (`mfnd serve --p2p-listen`) when using `--quorum-p2p`.

Weak-subjectivity (**M3.13** / **M3.18**): pin `get_light_snapshot.summary` fields in `wallet.json` (`--pin-trusted-summary`), verify an out-of-band file (`--trusted-summary FILE`), import-and-pin in one step (`light-scan --import-trusted-summary FILE`), or reset with `--reset-trusted-summary`. After each sync the pinned summary is refreshed from the evolved checkpoint (same as the browser demo).

Cap scan depth with `--max-height N` (**M3.21**) when the node tip is ahead of what you need (e.g. integration smokes that only require height 1).

Export a summary for distribution (**M3.14**):

```bash
mfn-cli wallet export-trusted-summary --out trusted-summary.json
mfn-cli wallet export-trusted-summary --from-wallet-checkpoint --pin
mfn-cli wallet import-trusted-summary trusted-summary.json --verify-checkpoint
```

Import (**M3.15**) pins an out-of-band JSON file into `wallet.json` without syncing; `--verify-checkpoint` checks the file against persisted `light_checkpoint_hex` when present.

Three-validator devnet (**M3.17**): unit test asserts `validator_count=3` on a three-validator genesis checkpoint; live `light_scan_three_validator_smoke` mesh harness is `#[ignore]` (nightly `scripts/ci-ignored.sh`). Genesis spec: `mfn-node/testdata/devnet_three_validators_wallet_payout.json`.

Inspect and diff (**M3.16**):

```bash
mfn-cli wallet show-trusted-summary
mfn-cli wallet show-trusted-summary --from-checkpoint --json
mfn-cli wallet compare-trusted-summary trusted-summary.json
mfn-cli wallet compare-trusted-summary a.json b.json
```

`wallet status` prints the cached balance and how many blocks behind the node tip you are without downloading blocks. Add `--json` for stuck-wallet diagnostics or support tickets; the structured output includes `tip_height`, `scan_height`, `blocks_behind`, `sync_needed`, cached balance/owned counts, pending-spend count, and light-summary presence without revealing the seed.

`wallet send` syncs the chain, loads UTXO set + `get_checkpoint` for decoys, builds a CLSAG transfer with [`Wallet::build_transfer`](../mfn-wallet/src/wallet.rs), and broadcasts via `submit_tx`. Locally spent inputs are recorded in `pending_spent_utxo_keys` until the tx mines.

`wallet upload` reads a file (≤ 32 MiB), validates fee/replication against chain endowment rules via [`Wallet::build_storage_upload`](../mfn-wallet/src/upload.rs), prints `data_root` and `storage_commitment_hash`, and submits the signed tx. With `--message`, it uses [`Wallet::build_storage_upload_with_authorship`](../mfn-wallet/src/wallet.rs) to pack a storage-bound MFCL claim in `tx.extra` (mutually exclusive with `--extra`). **M3.24** persists `payload.bin` + `meta.bytes` under `{wallet_stem}.upload-artifacts/<commit_hash>/` so operators can prove without keeping the original path.

`wallet claim` derives a deterministic [`ClaimingIdentity`](../mfn-wallet/src/claiming.rs) from the wallet seed, signs an MFCL claim over `DATA_ROOT_HEX` via [`Wallet::publish_claim_tx`](../mfn-wallet/src/wallet.rs), and submits it. Use `--commit-hash` to bind the claim to a storage commitment hash from a prior upload.

Storage operators (**M3.22**) answer SPoRA challenges for anchored data:

```bash
mfn-cli uploads list
mfn-cli --wallet ./alice.json uploads local
mfn-cli operator challenge <COMMITMENT_HASH_HEX>
mfn-cli operator prove <COMMITMENT_HASH_HEX> ./same-bytes-as-upload.bin
mfn-cli --wallet ./alice.json operator prove <COMMITMENT_HASH_HEX>
mfn-cli --wallet ./alice.json operator artifacts --json
mfn-cli operator pool
```

`operator prove` rebuilds the Merkle tree from local file bytes (or from the wallet upload artifact when FILE is omitted and `--wallet` is set), verifies `data_root`, builds the proof for the next block, and queues it via `submit_storage_proof`. Validators include queued proofs when producing the next block (`mfnd serve --produce` or `mfnd step`).

Queued proofs persist in `proof_pool.bytes` under the node data directory (**M3.23**), the same way mempool txs use `mempool.bytes` — survive `mfnd serve` restarts until mined or cleared.

`uploads local` and `operator artifacts` (**M3.25**) enumerate `{wallet_stem}.upload-artifacts/` so you can copy `commitment_hash` into `operator prove` without hunting directories by hand. The summary includes total `artifacts_payload_bytes` for backup sizing. Add `--json` to either command for structured backup manifests.

`uploads status` (**M3.26**) pages `list_recent_uploads` and joins on commitment hash so operators see `matched`, `local_only` (artifact without chain index row), and `chain_only` (indexed upload missing local `payload.bin`). It also prints `local_artifacts_payload_bytes` for backup planning. Add `--json` for automation-friendly reconciliation output.

`uploads retrieve HASH OUT [replace]` (**M3.27**) exports `payload.bin` from a wallet-local artifact to `OUT`. It works after the original `wallet upload`, HTTP backfill, or P2P inbox assembly, and refuses to overwrite an existing file unless the final argument is `replace`. Use `operator inbox-status HASH DATA_DIR --json` to script checks for missing P2P-replicated chunks before assembly, then `operator assemble-inbox HASH DATA_DIR --json` to capture the created artifact path and payload size.

`uploads fetch-http HASH OUT PEER [PEER...] [replace]` (**M3.28**) fetches all chunks from one or more HTTP chunk peers into the wallet artifact tree, verifies them against the on-chain storage challenge, then writes the restored payload to `OUT`. Multiple peers require byte-identical chunks. Add `--json` to capture the rebuilt `artifact_dir`, restored `output_path`, `payload_bytes`, peer list, and quorum size; use `operator backfill HASH PEER [PEER...] --json` when you only need to rebuild the wallet artifact.

For continuous proving, run the storage-operator daemon (**M6**):

```bash
cargo build -p mfn-storage-operator --release
mfn-storage-operator run --wallet ./alice.json --rpc 127.0.0.1:18731
```

See [`mfn-storage-operator/README.md`](../mfn-storage-operator/README.md). Integration smokes in `tests/storage_operator_smoke.rs` (**M6.1**) cover `operator prove` → `mfnd step` → `uploads list` / `uploads status`, and `mfn-storage-operator run --once`.

To mine any wallet tx: stop `mfnd serve` (flushes `mempool.bytes`), then `mfnd step --blocks 1` (reloads durable mempool per **M2.3.21**).

## Library

```rust
use mfn_cli::RpcClient;

let mut client = RpcClient::new("127.0.0.1:18731");
let tip = client.get_tip()?;
```

## Tests

```bash
cargo test -p mfn-cli
```

Integration tests spawn `mfnd serve` on an ephemeral port.
