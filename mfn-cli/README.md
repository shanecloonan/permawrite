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
mfn-cli wallet balance

# Send (CLSAG transfer + submit_tx; mine with `mfnd step` after stopping serve)
mfn-cli --rpc 127.0.0.1:<PORT> wallet send <VIEW_PUB_HEX> <SPEND_PUB_HEX> <AMOUNT> \
  --fee 10000 --ring-size 8

# Permanent storage upload (anchor to self; fee defaults to upload_min_fee + tip)
mfn-cli --rpc 127.0.0.1:<PORT> wallet upload ./document.bin --replication 3

# Authorship claim (MFCL in tx.extra; unbound unless --commit-hash set)
mfn-cli --rpc 127.0.0.1:<PORT> wallet claim <DATA_ROOT_HEX> --message "hello permanence"
```

Default RPC address: `127.0.0.1:18731` (mfnd default `--rpc-listen`).

Default wallet file: `wallet.json` (override with `--wallet PATH`). The file stores a 32-byte `seed_hex` and optional `scan_height`. **Back it up** — it is the only recovery path for funds.

`wallet scan` / `wallet balance` fetch blocks from `scan_height + 1` (or genesis height `1` on first run) through the node tip via `get_block`, decode with `mfn-consensus`, and feed [`Wallet::ingest_block`](../mfn-wallet/src/wallet.rs). Persistent UTXO snapshots on disk are a later optimization.

`wallet send` syncs the chain, loads UTXO set + `get_checkpoint` for decoys, builds a CLSAG transfer with [`Wallet::build_transfer`](../mfn-wallet/src/wallet.rs), and broadcasts via `submit_tx`. Locally spent inputs are recorded in `pending_spent_utxo_keys` until the tx mines.

`wallet upload` reads a file (≤ 32 MiB), validates fee/replication against chain endowment rules via [`Wallet::build_storage_upload`](../mfn-wallet/src/upload.rs), prints `data_root` and `storage_commitment_hash`, and submits the signed tx. Keep the file bytes locally for SPoRA chunk proofs.

`wallet claim` derives a deterministic [`ClaimingIdentity`](../mfn-wallet/src/claiming.rs) from the wallet seed, signs an MFCL claim over `DATA_ROOT_HEX` via [`Wallet::publish_claim_tx`](../mfn-wallet/src/wallet.rs), and submits it. Use `--commit-hash` to bind the claim to a storage commitment hash from a prior upload.

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
