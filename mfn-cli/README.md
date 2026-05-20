# `mfn-cli`

Operator CLI for Permawrite (**M3.0** / **M3.1**): talks to a running [`mfnd`](../mfn-node) node over newline-delimited JSON-RPC 2.0 and drives [`mfn-wallet`](../mfn-wallet) for local key material + chain scanning.


## Build

```bash
cargo build -p mfn-cli --release
```

## Usage

```bash
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
mfn-cli wallet address
mfn-cli --wallet ./alice.json wallet scan
mfn-cli wallet light-scan
mfn-cli wallet balance

# Send (CLSAG transfer + submit_tx; mine with `mfnd step` after stopping serve)
mfn-cli --rpc 127.0.0.1:<PORT> wallet send <VIEW_PUB_HEX> <SPEND_PUB_HEX> <AMOUNT> \
  --fee 10000 --ring-size 8

# Permanent storage upload (anchor to self; fee defaults to upload_min_fee + tip)
mfn-cli --rpc 127.0.0.1:<PORT> wallet upload ./document.bin --replication 3

# Upload with MFCL authorship claim bound to data_root + commitment hash
mfn-cli --rpc 127.0.0.1:<PORT> wallet upload ./document.bin --message "signed by me"

# Authorship claim (MFCL in tx.extra; unbound unless --commit-hash set)
mfn-cli --rpc 127.0.0.1:<PORT> wallet claim <DATA_ROOT_HEX> --message "hello permanence"
```

Default RPC address: `127.0.0.1:18731` (mfnd default `--rpc-listen`).

Default wallet file: `wallet.json` (override with `--wallet PATH`). The file stores a 32-byte `seed_hex` and optional `scan_height`. **Back it up** — it is the only recovery path for funds.

`wallet scan` / `wallet balance` fetch full blocks via `get_block` after the persisted `scan_height` when `owned_outputs` is populated (**M3.6**); otherwise they replay from height `1`.

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

`wallet status` prints the cached balance and how many blocks behind the node tip you are without downloading blocks.

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
mfn-cli --wallet ./alice.json operator artifacts
mfn-cli operator pool
```

`operator prove` rebuilds the Merkle tree from local file bytes (or from the wallet upload artifact when FILE is omitted and `--wallet` is set), verifies `data_root`, builds the proof for the next block, and queues it via `submit_storage_proof`. Validators include queued proofs when producing the next block (`mfnd serve --produce` or `mfnd step`).

Queued proofs persist in `proof_pool.bytes` under the node data directory (**M3.23**), the same way mempool txs use `mempool.bytes` — survive `mfnd serve` restarts until mined or cleared.

`uploads local` and `operator artifacts` (**M3.25**) enumerate `{wallet_stem}.upload-artifacts/` so you can copy `commitment_hash` into `operator prove` without hunting directories by hand.

`uploads status` (**M3.26**) pages `list_recent_uploads` and joins on commitment hash so operators see `matched`, `local_only` (artifact without chain index row), and `chain_only` (indexed upload missing local `payload.bin`).

For continuous proving, run the storage-operator daemon (**M6**):

```bash
cargo build -p mfn-storage-operator --release
mfn-storage-operator run --wallet ./alice.json --rpc 127.0.0.1:18731
```

See [`mfn-storage-operator/README.md`](../mfn-storage-operator/README.md).

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
